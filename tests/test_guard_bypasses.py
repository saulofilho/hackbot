"""Regressoes para bypasses do scope guard encontrados ao portar os guardrails
para o scopehound. Nada aqui toca rede ou DNS reais: resolver e transporte
sao falsos."""
import ast
import ipaddress

import httpx
import pytest

from hackbot.budget import Budget
from hackbot.config import Settings, TargetScope
from hackbot.scope_guard import (
    ScopeViolation,
    Target,
    check_target,
    normalize_path,
    resolve_target,
)
from hackbot.tools import _new_client, make_tools, sanitize_sqlmap_args


def _scope(**kw):
    base = {
        "allowed_hosts": ["localhost", "app.lab", "*.lab"],
        "allowed_paths": ["/*"],
        "exclude_paths": ["/logout", "/admin/delete"],
        "authorized_by": "x",
    }
    base.update(kw)
    return TargetScope(**base)


def _check(url, scope=None):
    return check_target(Target(url), scope or _scope(), 0, 100)


def _resolver(mapping):
    async def resolve(host, port):
        return [ipaddress.ip_address(ip) for ip in mapping[host]]

    return resolve


# ---------------------------------------------------------------------------
# 1. Resolved IP validation (SSRF / DNS rebinding) and pinned connection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ips",
    [
        ["169.254.169.254"],
        ["10.0.0.5"],
        ["192.168.1.1"],
        ["127.0.0.1"],
        ["::ffff:169.254.169.254"],  # IPv4-mapped IPv6
        ["fd00:ec2::254"],
        ["93.184.216.34", "169.254.169.254"],  # one bad IP among good ones
    ],
)
async def test_allowed_host_resolving_to_internal_or_metadata_is_denied(ips):
    checked = _check("http://app.lab/")
    with pytest.raises(ScopeViolation):
        await resolve_target(checked, _scope(), _resolver({"app.lab": ips}))


async def test_public_ip_is_allowed():
    checked = _check("http://app.lab/")
    ips = await resolve_target(checked, _scope(), _resolver({"app.lab": ["93.184.216.34"]}))
    assert [str(i) for i in ips] == ["93.184.216.34"]


async def test_internal_ip_allowed_when_cidr_authorized():
    scope = _scope(allowed_cidrs=["10.10.10.0/24"])
    checked = _check("http://app.lab/", scope)
    await resolve_target(checked, scope, _resolver({"app.lab": ["10.10.10.7"]}))


async def test_metadata_denied_even_when_cidr_authorized():
    scope = _scope(allowed_cidrs=["169.254.0.0/16"])
    with pytest.raises(ScopeViolation):
        await resolve_target(_check("http://169.254.169.254/", scope), scope)
    checked = _check("http://app.lab/", scope)
    with pytest.raises(ScopeViolation):
        await resolve_target(checked, scope, _resolver({"app.lab": ["169.254.169.254"]}))


async def test_localhost_loopback_and_literal_ip_hosts_allowed():
    scope = _scope(allowed_hosts=["localhost", "127.0.0.1"])
    await resolve_target(_check("http://localhost:3000/", scope), scope, _resolver({"localhost": ["127.0.0.1", "::1"]}))
    await resolve_target(_check("http://127.0.0.1:3000/", scope), scope)


async def test_localhost_resolving_elsewhere_internal_is_denied():
    checked = _check("http://localhost/")
    with pytest.raises(ScopeViolation):
        await resolve_target(checked, _scope(), _resolver({"localhost": ["10.0.0.1"]}))


def _live_tools(transport, resolver, **scope_kw):
    settings = Settings(dry_run=False, require_authorization=False)
    scope = _scope(max_requests_per_second=1000, **scope_kw)
    budget = Budget(max_steps=50, max_requests=50, max_tokens=100_000)
    findings: list = []
    actions: list = []
    tools = make_tools(
        settings, scope, budget, findings, actions, resolver=resolver, transport=transport
    )
    return {t.name: t for t in tools}, budget


async def test_http_probe_connects_to_validated_ip_with_original_host_and_sni():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text="ok")

    tools, _ = _live_tools(
        httpx.MockTransport(handler), _resolver({"app.lab": ["93.184.216.34"]})
    )
    r = await tools["http_probe"].ainvoke({"url": "https://app.lab:8443/api?q=1"})
    assert "-> 200" in r
    (req,) = seen
    assert req.url.host == "93.184.216.34"
    assert req.url.port == 8443
    assert req.url.raw_path == b"/api?q=1"
    assert req.headers["host"] == "app.lab:8443"
    assert req.extensions["sni_hostname"] == "app.lab"


async def test_http_probe_rebinding_to_metadata_sends_nothing():
    seen: list = []
    tools, budget = _live_tools(
        httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200)),
        _resolver({"app.lab": ["169.254.169.254"]}),
    )
    r = await tools["http_probe"].ainvoke({"url": "http://app.lab/"})
    assert "VIOLACAO" in r
    assert seen == []
    assert budget.requests == 0


async def test_scan_js_bundle_does_not_follow_redirect_out_of_scope():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "http://evil.com/x.js"})

    tools, _ = _live_tools(
        httpx.MockTransport(handler), _resolver({"app.lab": ["93.184.216.34"]})
    )
    r = await tools["scan_js_bundle"].ainvoke({"url": "http://app.lab/main.js"})
    assert "VIOLACAO" in r
    assert len(seen) == 1


async def test_scan_js_bundle_redirect_to_metadata_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    tools, _ = _live_tools(
        httpx.MockTransport(handler),
        _resolver({"app.lab": ["93.184.216.34"]}),
        allowed_hosts=["app.lab", "169.254.169.254"],
    )
    r = await tools["scan_js_bundle"].ainvoke({"url": "http://app.lab/main.js"})
    assert "VIOLACAO" in r


# ---------------------------------------------------------------------------
# 2. Path normalization before exclude/allow matching
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path",
    [
        "/logout",
        "/Logout",
        "/LOGOUT",
        "/logout/",
        "//logout",
        "/%6cogout",
        "/%4Cogout",
        "/logout;x",
        "/logout;jsessionid=1",
        "/x/../logout",
        "/./logout",
        "/logout/now",
        "/admin//delete",
        "/admin/./delete",
        "/Admin/Delete/",
    ],
)
def test_excluded_path_variants_blocked(path):
    with pytest.raises(ScopeViolation):
        _check(f"http://localhost{path}")


@pytest.mark.parametrize("path", ["/%252e%252e/logout", "/../logout", "/%2e%2e/etc"])
def test_double_encoding_and_root_escape_rejected(path):
    with pytest.raises(ScopeViolation):
        _check(f"http://localhost{path}")


def test_similar_but_distinct_paths_still_allowed():
    _check("http://localhost/logouts")
    _check("http://localhost/api/logout-info")


def test_normalize_path_examples():
    assert normalize_path("//a/./b/../c;x/") == "/a/c/"
    assert normalize_path("/%61pi?x=/logout") == "/api"


def test_allowed_paths_use_normalized_path():
    scope = _scope(allowed_paths=["/api/*"])
    _check("http://localhost/api/users", scope)
    with pytest.raises(ScopeViolation):
        _check("http://localhost/api/../private", scope)


# ---------------------------------------------------------------------------
# 3. userinfo / backslashes / odd schemes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://user:pass@localhost/",
        "http://localhost@evil.com/",
        "http://evil.com@localhost/",
        "http://localhost\\@evil.com/",
        "http://localhost\\evil.com/",
        "http://localhost/a\\..\\logout",
        "http://localhost/a b",
        "http://localhost/\x00",
        "file:///etc/passwd",
        "gopher://localhost/",
    ],
)
def test_malformed_or_ambiguous_urls_rejected(url):
    with pytest.raises(ScopeViolation):
        _check(url)


def test_host_case_and_trailing_dot_normalized():
    assert _check("http://APP.LAB./").host == "app.lab"


# ---------------------------------------------------------------------------
# 4. sqlmap allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "extra",
    [
        "-u http://evil.com/?id=1",
        "-u=http://evil.com/?id=1",
        "--url=http://evil.com/",
        "-m targets.txt",
        "-g inurl:id=",
        "-l burp.log",
        "-r req.txt",
        "--alert=id",
        "--proxy=http://evil.com:8080",
        "--tamper=/tmp/evil.py",
        "--os-sh",  # optparse prefix of --os-shell
        "--file-r=/etc/passwd",
        "--os-shell",
        "--dump-all",
        "--eval=import os",
        "-v3",
        "positional",
        "--cookie --os-shell",  # value smuggling a flag
        "-H Host:evil.com",
        '--headers="X-A:1\\nHost:evil.com"',  # literal \n, as sqlmap splits it
        "--threads=abc",
        "--batch=1",
    ],
)
def test_sqlmap_args_outside_allowlist_rejected(extra):
    import shlex

    from hackbot.tools import ToolArgsDenied

    with pytest.raises(ToolArgsDenied):
        sanitize_sqlmap_args(shlex.split(extra))


def test_sqlmap_allowlisted_args_pass_and_are_clamped():
    out = sanitize_sqlmap_args(
        ["-p", "id", "--dbms=mysql", "--threads=10", "--risk=3", "--level", "5", "--banner"]
    )
    assert out == [
        "--batch", "--risk=1", "--level=1", "-p", "id", "--dbms", "mysql", "--threads", "4", "--banner"
    ]


async def test_sqlmap_tool_blocks_target_override():
    settings = Settings(dry_run=True, require_authorization=False, enable_external_tools=True)
    budget = Budget(max_steps=50, max_requests=50, max_tokens=100_000)
    tools = {
        t.name: t
        for t in make_tools(
            settings, _scope(), budget, [], [], resolver=_resolver({"localhost": ["127.0.0.1"]})
        )
    }
    r = await tools["sqlmap_scan"].ainvoke(
        {"url": "http://localhost/?id=1", "extra_args": "-u http://evil.com/?id=1"}
    )
    assert "BLOQUEADO" in r
    assert "evil.com" not in r.split("BLOQUEADO", 1)[0]


# ---------------------------------------------------------------------------
# 5. Host header must match the target
# ---------------------------------------------------------------------------

async def test_http_probe_rejects_mismatched_host_header():
    seen: list = []
    tools, _ = _live_tools(
        httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200)),
        _resolver({"app.lab": ["93.184.216.34"]}),
    )
    for name in ("Host", "host", " HOST "):
        r = await tools["http_probe"].ainvoke(
            {"url": "http://app.lab/", "headers": {name: "internal-admin.corp"}}
        )
        assert "VIOLACAO" in r
    r = await tools["verify_finding"].ainvoke(
        {"title": "t", "severity": "LOW", "url": "http://app.lab/",
         "expected_status": 200, "headers": {"Host": "evil.com"}}
    )
    assert "NAO_VERIFICADO" in r
    assert seen == []


async def test_http_probe_accepts_matching_host_header():
    seen: list[httpx.Request] = []
    tools, _ = _live_tools(
        httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200)),
        _resolver({"app.lab": ["93.184.216.34"]}),
    )
    r = await tools["http_probe"].ainvoke({"url": "http://app.lab/", "headers": {"Host": "APP.LAB"}})
    assert "-> 200" in r
    assert seen[0].headers.get_list("host") == ["app.lab"]


# ---------------------------------------------------------------------------
# 6. Environment proxies are ignored
# ---------------------------------------------------------------------------

async def test_http_client_ignores_proxy_env(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://attacker.example:8080")
    async with _new_client(5.0) as client:
        assert client.trust_env is False
        assert not client._mounts  # no proxy transports were mounted from env


# ---------------------------------------------------------------------------
# 7. ffuf: allowlist for extra_args, FUZZ only in path/query, wordlist filter
# ---------------------------------------------------------------------------

def _ffuf_tools(tmp_path, dry_run=True, **scope_kw):
    settings = Settings(
        dry_run=dry_run,
        require_authorization=False,
        enable_external_tools=True,
        ffuf_bin=str(tmp_path / "fake-ffuf"),
    )
    budget = Budget(max_steps=50, max_requests=50, max_tokens=100_000)
    tools = make_tools(
        settings, _scope(**scope_kw), budget, [], [],
        resolver=_resolver({"localhost": ["127.0.0.1"], "app.lab": ["93.184.216.34"]}),
    )
    return {t.name: t for t in tools}


@pytest.mark.parametrize(
    "extra",
    [
        "-u http://evil.com/FUZZ",
        "--u=http://evil.com/FUZZ",
        "-x http://evil.com:8080",
        "-replay-proxy http://evil.com:8080",
        "-request req.txt",
        "-input-cmd id",
        "-input-file /etc/passwd",
        "-w /etc/passwd:FUZZ",
        "-config evil.toml",
        "-o /tmp/out.json",
        "-od /tmp",
        "-debug-log /tmp/x",
        "-r",
        "-recursion",
        "-sni evil.com",
        "-H Host:evil.com",
        "-H 'host : evil.com'",
        "-X DELETE",
        "-e .php,/../logout",
        "-t lots",
        "-ac=false",
        "positional",
        "-mc -x",
    ],
)
def test_ffuf_args_outside_allowlist_rejected(extra):
    import shlex

    from hackbot.tools import ToolArgsDenied, sanitize_ffuf_args

    with pytest.raises(ToolArgsDenied):
        sanitize_ffuf_args(shlex.split(extra), 5.0)


def test_ffuf_allowlisted_args_pass_rate_forced_threads_clamped():
    from hackbot.tools import sanitize_ffuf_args

    out = sanitize_ffuf_args(
        ["--mc=200,301", "-fs", "0", "-t", "100", "-rate", "999", "-e", ".php,.bak", "-ac"], 3.0
    )
    assert out == [
        "-noninteractive", "-rate", "3",
        "-mc", "200,301", "-fs", "0", "-t", "10", "-e", ".php,.bak", "-ac",
    ]


@pytest.mark.parametrize(
    "url",
    ["http://FUZZ.lab/", "http://app.FUZZ/", "http://localhost:FUZZ/", "http://FUZZ@localhost/"],
)
async def test_ffuf_fuzz_marker_outside_path_rejected(tmp_path, url):
    tools = _ffuf_tools(tmp_path)
    r = await tools["ffuf_scan"].ainvoke({"url": url, "wordlist": "w.txt"})
    assert "VIOLACAO" in r


async def test_ffuf_tool_blocks_target_override(tmp_path):
    tools = _ffuf_tools(tmp_path)
    r = await tools["ffuf_scan"].ainvoke(
        {"url": "http://localhost/FUZZ", "wordlist": "w.txt", "extra_args": "-u http://evil.com/FUZZ"}
    )
    assert "BLOQUEADO" in r


def test_filter_ffuf_wordlist_drops_excluded_and_escaping_words():
    from hackbot.tools import filter_ffuf_wordlist

    words = ["api", "logout", "Logout", "x/../logout", "%6cogout", "admin/delete", "a\\b",
             "../../logout", "users", "logout;x"]
    kept, dropped = filter_ffuf_wordlist("http://localhost/FUZZ", words, [], _scope())
    assert kept == ["api", "users"]
    assert dropped == len(words) - 2
    # extensions are checked too: "log" + "out" lands on /logout
    kept, _ = filter_ffuf_wordlist("http://localhost/FUZZ", ["log", "ok"], ["out"], _scope())
    assert kept == ["ok"]


async def test_ffuf_live_runs_with_filtered_wordlist(tmp_path):
    import os
    import sys

    record = tmp_path / "record.txt"
    fake = tmp_path / "fake-ffuf"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "w = sys.argv[sys.argv.index('-w') + 1]\n"
        f"open({str(record)!r}, 'w').write(repr(sys.argv[1:]) + '\\n' + open(w).read())\n"
    )
    os.chmod(fake, 0o755)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("api\nlogout\n../../admin/delete\nusers\n\n")
    tools = _ffuf_tools(tmp_path, dry_run=False)
    r = await tools["ffuf_scan"].ainvoke(
        {"url": "http://localhost/FUZZ", "wordlist": str(wordlist), "extra_args": "-mc 200"}
    )
    assert "exit=0" in r
    assert "2 removidas" in r
    argv_line, *sent_words = record.read_text().splitlines()
    assert sent_words == ["api", "users"]
    argv = ast.literal_eval(argv_line)
    assert argv[argv.index("-u") + 1] == "http://localhost/FUZZ"
    assert argv[argv.index("-w") + 1] != str(wordlist)  # filtered temp copy
    assert not os.path.exists(argv[argv.index("-w") + 1])  # and it was cleaned up
    assert argv[argv.index("-rate") + 1] == "5"  # scope default rps


async def test_ffuf_all_words_out_of_scope_runs_nothing(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("logout\nLOGOUT/\n")
    tools = _ffuf_tools(tmp_path, dry_run=False)
    r = await tools["ffuf_scan"].ainvoke({"url": "http://localhost/FUZZ", "wordlist": str(wordlist)})
    assert "VIOLACAO" in r
    assert not (tmp_path / "record.txt").exists()
