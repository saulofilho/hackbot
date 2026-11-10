from __future__ import annotations

import asyncio
import itertools
import os
import re
import shlex
import tempfile
from typing import Any

import httpx
from langchain_core.tools import tool

from .budget import Budget, BudgetExhausted
from .config import Settings, TargetScope
from .scope_guard import (
    CheckedTarget,
    IPAddress,
    Resolver,
    ScopeViolation,
    Target,
    authority_of,
    check_target,
    resolve_target,
    system_resolver,
)

SECRET_PATTERNS = {
    "aws_akid": re.compile(r"AKIA[0-9A-Z]{16}"),
    "openai": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# sqlmap: allowlist, not a denylist. Any flag not listed here is rejected.
# A denylist let through `-u` (swaps the target, escaping scope), `-m`/`-l`/`-g`
# (targets from a file/log/Google), `--alert` (runs a command on this host),
# `--proxy`, `--tamper` (loads arbitrary Python) and abbreviations of denied
# flags (optparse accepts unique prefixes like `--os-sh`).
SQLMAP_FORCED = ("--batch", "--risk=1", "--level=1")
_SQLMAP_SWITCHES = frozenset({
    "--batch", "--random-agent", "--banner", "--current-user", "--current-db",
    "--is-dba", "--dbs", "--tables", "--columns", "--count", "--skip-static",
    "--flush-session", "--fresh-queries", "--text-only", "--titles", "--smart",
    "--keep-alive", "--null-connection", "--hex", "--no-cast", "--parse-errors",
})
_SQLMAP_OPTIONS = frozenset({
    "-p", "--technique", "--dbms", "--string", "--not-string", "--regexp", "--code",
    "--prefix", "--suffix", "--timeout", "--retries", "--delay", "--cookie",
    "--cookie-del", "--headers", "-H", "--method", "--param-del", "-D", "-T", "-C",
    "--skip", "--time-sec", "--union-cols", "--union-char", "--threads", "-v",
})
_SQLMAP_DROPPED = frozenset({"--risk", "--level"})  # silently replaced by SQLMAP_FORCED
_SQLMAP_MAX_THREADS = 4
MAX_JS_REDIRECTS = 5
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class ToolArgsDenied(ValueError):
    """Argumento de ferramenta externa fora da allowlist."""


def sanitize_sqlmap_args(tokens: list[str]) -> list[str]:
    """Valida extra_args do sqlmap contra a allowlist e devolve a lista final
    com os parametros obrigatorios (`--batch --risk=1 --level=1`) na frente."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("-"):
            raise ToolArgsDenied(f"argumento posicional nao permitido: {token!r}")
        name, has_value, value = token.partition("=")
        if name in _SQLMAP_DROPPED:
            i += 1 if has_value else 2
            continue
        if name in _SQLMAP_SWITCHES:
            if has_value:
                raise ToolArgsDenied(f"{name} nao aceita valor")
            out.append(name)
            i += 1
            continue
        if name not in _SQLMAP_OPTIONS:
            raise ToolArgsDenied(f"flag nao permitida no sqlmap: {name}")
        if not has_value:
            if i + 1 >= len(tokens):
                raise ToolArgsDenied(f"{name} precisa de um valor")
            value = tokens[i + 1]
            i += 2
        else:
            i += 1
        if not value or value.startswith("-"):
            raise ToolArgsDenied(f"valor invalido para {name}: {value!r}")
        if name in ("--headers", "-H") and any(
            line.strip().lower().startswith("host:") for line in re.split(r"\\n|\n", value)
        ):
            raise ToolArgsDenied("cabecalho Host nao pode ser alterado")
        if name == "--threads":
            try:
                threads = int(value)
            except ValueError as exc:
                raise ToolArgsDenied(f"--threads invalido: {value!r}") from exc
            value = str(max(1, min(threads, _SQLMAP_MAX_THREADS)))
        out += [name, value]
    return [*SQLMAP_FORCED, *out]


# ffuf: same idea. Go's flag package accepts `-flag` and `--flag` (no prefix
# abbreviation), so both spellings are normalized to `-flag`. Not allowed:
# `-u` (target swap), `-x`/`-replay-proxy`, `-request` (raw request with its own
# Host), `-input-cmd` (runs a command), `-w`/`-input-file`/`-config` (extra
# inputs), `-o`/`-od`/`-debug-log` (writes files), `-r`/`-recursion` (follows
# the server off the checked URL), `-sni`, and anything else not listed.
FFUF_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})
_FFUF_SWITCHES = frozenset({"-ac", "-ic", "-s", "-c", "-v", "-sa", "-se", "-sf"})
_FFUF_OPTIONS = frozenset({
    "-H", "-X", "-d", "-b", "-e", "-t", "-p", "-timeout", "-maxtime", "-maxtime-job",
    "-mc", "-ms", "-mw", "-ml", "-mr", "-mt", "-mmode",
    "-fc", "-fs", "-fw", "-fl", "-fr", "-ft", "-fmode",
})
_FFUF_DROPPED = frozenset({"-rate"})  # forced from scope.max_requests_per_second
_FFUF_MAX_THREADS = 10
_FFUF_EXTENSION = re.compile(r"^\.?[A-Za-z0-9_-]{1,16}$")


def sanitize_ffuf_args(tokens: list[str], rate: float) -> list[str]:
    """Valida extra_args do ffuf contra a allowlist. Devolve a lista final com
    `-noninteractive` e `-rate` (do escopo) forcados."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("-"):
            raise ToolArgsDenied(f"argumento posicional nao permitido: {token!r}")
        name, has_value, value = token.partition("=")
        if name.startswith("--"):
            name = name[1:]
        if name in _FFUF_DROPPED:
            i += 1 if has_value else 2
            continue
        if name in _FFUF_SWITCHES:
            if has_value:
                raise ToolArgsDenied(f"{name} nao aceita valor")
            out.append(name)
            i += 1
            continue
        if name not in _FFUF_OPTIONS:
            raise ToolArgsDenied(f"flag nao permitida no ffuf: {name}")
        if not has_value:
            if i + 1 >= len(tokens):
                raise ToolArgsDenied(f"{name} precisa de um valor")
            value = tokens[i + 1]
            i += 2
        else:
            i += 1
        if not value or value.startswith("-"):
            raise ToolArgsDenied(f"valor invalido para {name}: {value!r}")
        if name == "-H" and value.split(":", 1)[0].strip().lower() == "host":
            raise ToolArgsDenied("cabecalho Host nao pode ser alterado")
        if name == "-X" and value.upper() not in FFUF_ALLOWED_METHODS:
            raise ToolArgsDenied(f"metodo nao permitido: {value}")
        if name == "-e" and not all(_FFUF_EXTENSION.match(e) for e in value.split(",")):
            raise ToolArgsDenied(f"extensoes invalidas: {value!r}")
        if name == "-t":
            try:
                threads = int(value)
            except ValueError as exc:
                raise ToolArgsDenied(f"-t invalido: {value!r}") from exc
            value = str(max(1, min(threads, _FFUF_MAX_THREADS)))
        out += [name, value]
    return ["-noninteractive", "-rate", str(max(1, int(rate))), *out]


def ffuf_extensions(args: list[str]) -> list[str]:
    exts: list[str] = []
    for name, value in itertools.pairwise(args):
        if name == "-e":
            exts += value.split(",")
    return exts


def filter_ffuf_wordlist(
    url: str, words: list[str], extensions: list[str], scope: TargetScope
) -> tuple[list[str], int]:
    """ffuf so ve a URL com FUZZ; cada palavra substituida pode cair num path
    excluido (`logout`, `../admin/delete`). Mantem so as palavras cujas URLs
    finais (palavra e palavra+extensao, como o ffuf gera) passam no escopo."""
    kept: list[str] = []
    dropped = 0
    for word in words:
        variants = [word] + [word + ext for ext in extensions]
        try:
            for variant in variants:
                check_target(Target(url.replace("FUZZ", variant)), scope, 0, 1)
        except ScopeViolation:
            dropped += 1
            continue
        kept.append(word)
    return kept, dropped


def _write_filtered_wordlist(
    wordlist: str, url: str, extensions: list[str], scope: TargetScope
) -> tuple[str | None, int, int]:
    """Le o wordlist, filtra pelo escopo e grava as palavras mantidas num
    arquivo temporario. Devolve (caminho_ou_None, mantidas, removidas)."""
    with open(wordlist, encoding="utf-8", errors="replace") as fh:
        words = [line.rstrip("\r\n") for line in fh if line.strip()]
    kept, dropped = filter_ffuf_wordlist(url, words, extensions, scope)
    if not kept:
        return None, 0, dropped
    fd, path = tempfile.mkstemp(prefix="hackbot-ffuf-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(kept) + "\n")
    return path, len(kept), dropped


# --------------------------------------------------------------------------
# HTTP egress: every request connects to an already-validated IP (DNS
# pinning) with the original Host header and TLS SNI, so a second DNS
# resolution cannot redirect it (rebinding). trust_env=False so HTTP_PROXY /
# HTTPS_PROXY / ALL_PROXY in the environment cannot reroute traffic.
# --------------------------------------------------------------------------

def _new_client(
    timeout: float, transport: httpx.AsyncBaseTransport | None = None
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False, transport=transport
    )


def _prepare_headers(
    checked: CheckedTarget, user_agent: str, headers: dict[str, str] | None
) -> dict[str, str]:
    """Monta os headers. Um Host diferente do alvo e recusado: num IP
    permitido, um proxy reverso poderia encaminhar para fora do escopo."""
    prepared = {"User-Agent": user_agent}
    for name, value in (headers or {}).items():
        if name.strip().lower() == "host":
            if value.strip().lower() != checked.host_header.lower():
                raise ScopeViolation(f"cabecalho Host '{value}' difere do alvo '{checked.host_header}'")
            continue
        prepared[name] = value
    prepared["Host"] = checked.host_header
    return prepared


async def _pinned_send(
    client: httpx.AsyncClient,
    method: str,
    checked: CheckedTarget,
    ips: list[IPAddress],
    headers: dict[str, str],
    content: str | None,
) -> httpx.Response:
    extensions = {"sni_hostname": checked.host} if checked.scheme == "https" else {}
    last_error: httpx.HTTPError | None = None
    for ip in ips:
        request = client.build_request(
            method,
            checked.url.copy_with(host=str(ip)),
            headers=headers,
            content=content,
            extensions=extensions,
        )
        try:
            return await client.send(request)
        except httpx.ConnectError as exc:
            last_error = exc  # try the next IP (all of them already validated)
    assert last_error is not None
    raise last_error


# --------------------------------------------------------------------------
# JS analysis: regex secret scan + a real AST walk (via esprima) instead of
# naive substring checks. Both are module-level pure functions so they can be
# exercised directly in tests without spinning up the agent or the network.
# --------------------------------------------------------------------------

def _regex_secret_hits(text: str) -> list[str]:
    hits: list[str] = []
    for name, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(text):
            hits.append(f"{name}: {m.group(0)[:40]}...")
    return hits


def _callee_name(node: Any) -> str | None:
    """Resolve a Callee/MemberExpression AST node to a dotted name like 'document.cookie'."""
    if not isinstance(node, dict):
        return None
    t = node.get("type")
    if t == "Identifier":
        return node.get("name")
    if t == "MemberExpression":
        obj = _callee_name(node.get("object"))
        prop = node.get("property")
        prop_name = prop.get("name") if isinstance(prop, dict) else None
        if obj and prop_name:
            return f"{obj}.{prop_name}"
        return prop_name or obj
    return None


def _ast_scan(text: str, max_hits: int = 30) -> list[str]:
    """Walk a real JS AST (esprima) looking for dangerous calls, exfil sinks,
    and embedded secrets — far fewer false positives/negatives than grepping
    for the substring "eval(" in minified bundles.
    """
    try:
        import esprima
    except ImportError:
        return ["ast: esprima nao instalado — analise AST pulada (regex continua ativo)"]

    tree = None
    for parser in (esprima.parseScript, esprima.parseModule):
        try:
            tree = parser(text, options={"tolerant": True})
            break
        except Exception:  # noqa: BLE001, S112 — JS pulled from an untrusted
            continue        # target can raise anything from esprima's
            # internals (not just a documented esprima.Error); the only
            # correct behavior is "try the next parser mode", never crash
            # the agent loop over a scan target serving malformed JS.
    if tree is None:
        return ["ast: falha ao parsear o JS (script e module) — provavelmente nao e JS valido"]

    try:
        data = tree.toDict()
    except Exception as exc:  # noqa: BLE001 — same rationale: degrade to a
        return [f"ast: nao foi possivel converter a arvore ({exc})"]  # message, never raise.

    hits: list[str] = []
    DANGEROUS_CALLS = {"eval": "chamada perigosa a eval()", "Function": "execucao dinamica via Function()"}
    OBFUSCATION_CALLS = {"atob", "btoa", "unescape", "escape"}
    EXFIL_SINKS = {
        ("document", "cookie"), ("window", "localStorage"), ("window", "sessionStorage"),
        ("navigator", "sendBeacon"),
    }
    NETWORK_CALLS = {"fetch", "XMLHttpRequest"}

    def walk(node: Any) -> None:
        if len(hits) >= max_hits:
            return
        if isinstance(node, dict):
            t = node.get("type")
            if t in ("CallExpression", "NewExpression"):
                name = _callee_name(node.get("callee"))
                if name in DANGEROUS_CALLS:
                    hits.append(f"ast: {DANGEROUS_CALLS[name]}")
                elif name in OBFUSCATION_CALLS:
                    hits.append(f"ast: uso de {name}() (possivel ofuscacao/decoding)")
                elif name in NETWORK_CALLS:
                    hits.append(f"ast: chamada de rede via {name}(...)")
            elif t == "MemberExpression":
                obj = _callee_name(node.get("object"))
                prop = node.get("property")
                prop_name = prop.get("name") if isinstance(prop, dict) else None
                if obj and prop_name and (obj, prop_name) in EXFIL_SINKS:
                    hits.append(f"ast: acesso a {obj}.{prop_name} (sink sensivel)")
            elif t == "Literal":
                v = node.get("value")
                if isinstance(v, str) and len(v) >= 16:
                    for name, pat in SECRET_PATTERNS.items():
                        if pat.search(v):
                            hits.append(f"ast-literal {name}: {v[:40]}...")
                            break
            for k, v in node.items():
                if k == "type" or len(hits) >= max_hits:
                    continue
                walk(v)
        elif isinstance(node, list):
            for item in node:
                if len(hits) >= max_hits:
                    break
                walk(item)

    walk(data)
    return hits[:max_hits]


# --------------------------------------------------------------------------
# Subprocess runner shared by the external scanner wrappers. Always invoked
# via create_subprocess_exec (list argv, never shell=True) so nothing an
# agent passes as an argument can break out into a shell command.
# --------------------------------------------------------------------------

async def _run_subprocess(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return -1, "", f"binario nao encontrado no PATH: {cmd[0]}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"timeout apos {timeout}s"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def make_tools(
    settings: Settings,
    scope: TargetScope,
    budget: Budget,
    findings: list[dict[str, Any]],
    actions: list[str],
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list:
    """Factory: cria tools com closures sobre settings/scope/budget/coletores.
    `resolver` e `transport` existem para testes (DNS e rede falsos)."""

    async def _guard(url: str) -> tuple[CheckedTarget, list[IPAddress]] | str:
        """Shared scope check used by every network-facing tool: URL/host/path
        rules plus DNS resolution with every resolved IP validated. Returns
        (checked_target, validated_ips), or an error string on violation.
        """
        try:
            checked = check_target(Target(url), scope, budget.requests, settings.max_total_requests)
            ips = await resolve_target(checked, scope, resolver)
        except ScopeViolation as exc:
            return f"VIOLACAO: {exc}"
        return checked, ips

    async def _guard_or_none(url: str) -> str | None:
        result = await _guard(url)
        return result if isinstance(result, str) else None

    async def _do_http_request(
        url: str, method: str, headers: dict[str, str] | None, body: str
    ) -> tuple[bool, str, httpx.Response | None]:
        """Core of http_probe, factored out so verify_finding can replay the
        exact same guarded/budgeted/rate-limited request path.
        Returns (ok, message_or_dry_run_text, response_or_None).
        """
        guarded = await _guard(url)
        if isinstance(guarded, str):
            return False, guarded, None
        checked, ips = guarded
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}:
            return False, f"metodo nao permitido: {method}", None
        try:
            h = _prepare_headers(checked, settings.user_agent, headers)
        except ScopeViolation as exc:
            return False, f"VIOLACAO: {exc}", None
        if settings.dry_run:
            actions.append(f"DRY http_probe {method} {url}")
            return False, f"DRY_RUN: would {method} {url} (body={len(body)}B)", None
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return False, f"BUDGET: {exc}", None
        delay = 1.0 / max(scope.max_requests_per_second, 0.1)
        async with _new_client(15.0, transport) as client:
            try:
                resp = await _pinned_send(client, method, checked, ips, h, body or None)
            except httpx.HTTPError as exc:
                actions.append(f"ERR http_probe {method} {url}: {exc}")
                return False, f"ERRO: {exc}", None
        await asyncio.sleep(delay)
        actions.append(f"http_probe {method} {url} -> {resp.status_code}")
        return True, "ok", resp

    @tool
    async def check_scope(url: str) -> str:
        """Valida se a URL esta dentro do escopo autorizado. Use ANTES de qualquer requisicao."""
        violation = await _guard_or_none(url)
        return violation or f"OK: {url} dentro do escopo"

    @tool
    async def http_probe(
        url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str = ""
    ) -> str:
        """Faz requisicao HTTP ao alvo. Respeita scope, rate limit e dry_run."""
        ok, msg, resp = await _do_http_request(url, method, headers, body)
        if not ok:
            return msg
        snippet = resp.text[:500].replace("\n", " ")
        return (
            f"{method.upper()} {url} -> {resp.status_code}\n"
            f"headers: {dict(list(resp.headers.items())[:10])}\n"
            f"body[:500]: {snippet}"
        )

    @tool
    async def scan_js_bundle(url: str) -> str:
        """Baixa um arquivo JS e procura segredos (regex) e padroes perigosos via
        analise AST real (eval/Function, sinks de exfiltracao, chamadas de rede,
        literais que batem com padroes de segredo) — nao so grep de substring."""
        violation = await _guard_or_none(url)
        if violation:
            return violation
        if settings.dry_run:
            actions.append(f"DRY scan_js_bundle {url}")
            return f"DRY_RUN: would download, AST-parse and regex-scan {url}"
        # Redirects are followed by hand so every hop goes back through the
        # full scope + IP guard (httpx's follow_redirects would skip it).
        current = url
        async with _new_client(30.0, transport) as client:
            for _ in range(MAX_JS_REDIRECTS + 1):
                guarded = await _guard(current)
                if isinstance(guarded, str):
                    return f"{guarded} (redirect a partir de {url})"
                checked, ips = guarded
                try:
                    budget.request(1)
                except BudgetExhausted as exc:
                    return f"BUDGET: {exc}"
                headers = _prepare_headers(checked, settings.user_agent, None)
                try:
                    resp = await _pinned_send(client, "GET", checked, ips, headers, None)
                except httpx.HTTPError as exc:
                    return f"ERRO: {exc}"
                location = resp.headers.get("location")
                if resp.status_code not in _REDIRECT_CODES or not location:
                    break
                current = str(httpx.URL(current).join(location))
            else:
                return f"ERRO: mais de {MAX_JS_REDIRECTS} redirects a partir de {url}"
        text = resp.text
        regex_hits = _regex_secret_hits(text)
        ast_hits = _ast_scan(text)
        actions.append(
            f"scan_js_bundle {url} -> {len(regex_hits)} secrets (regex), {len(ast_hits)} ast findings"
        )
        return (
            f"JS {url} ({len(text)}B) status={resp.status_code}\n"
            f"segredos regex ({len(regex_hits)}): {regex_hits[:20]}\n"
            f"achados AST ({len(ast_hits)}): {ast_hits}"
        )

    @tool
    async def analyze_text_for_secrets(text: str) -> str:
        """Analisa um texto/trecho de JS colado: regex de segredos + analise AST
        (eval, sinks de exfiltracao, chamadas de rede)."""
        regex_hits = _regex_secret_hits(text)
        ast_hits = _ast_scan(text)
        return f"segredos regex ({len(regex_hits)}): {regex_hits[:20]}\nachados AST ({len(ast_hits)}): {ast_hits}"

    @tool
    async def save_finding(title: str, severity: str, evidence: str, url: str = "") -> str:
        """Registra um achado observacional. Severidade: CRITICAL/HIGH/MEDIUM/LOW/INFO.
        Para achados que dependem de um PoC reproduzivel (ex: IDOR, auth bypass),
        prefira `verify_finding`, que reexecuta a prova antes de registrar."""
        sev = severity.upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            sev = "INFO"
        findings.append(
            {
                "title": title,
                "severity": sev,
                "evidence": evidence[:2000],
                "url": url,
                "verified": False,
            }
        )
        actions.append(f"finding {sev}: {title}")
        return f"registrado (nao verificado): [{sev}] {title}"

    @tool
    async def verify_finding(
        title: str,
        severity: str,
        url: str,
        method: str = "GET",
        expected_status: int | None = None,
        expected_substring: str = "",
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> str:
        """Reexecuta o PoC (uma requisicao HTTP) e so registra o achado se a
        evidencia bater: status esperado e/ou substring esperada no corpo da
        resposta. Use isto em vez de save_finding sempre que o achado depender
        de uma condicao observavel e reproduzivel (IDOR, header ausente, bypass,
        segredo exposto em endpoint). Em dry_run, nada e enviado e nada e
        registrado como verificado."""
        if not expected_status and not expected_substring:
            return "ERRO: informe expected_status e/ou expected_substring para o PoC ser verificavel"
        ok, msg, resp = await _do_http_request(url, method, headers, body)
        if not ok:
            # covers VIOLACAO, dry_run, BUDGET and ERRO uniformly — never
            # auto-register an unverified finding in any of those cases.
            actions.append(f"verify_finding (nao executado): {title} -> {msg}")
            return f"NAO_VERIFICADO ({msg}): achado '{title}' NAO foi registrado"

        sev = severity.upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            sev = "INFO"
        status_ok = expected_status is None or resp.status_code == expected_status
        body_text = resp.text[:4000]
        substring_ok = not expected_substring or expected_substring in body_text
        if status_ok and substring_ok:
            evidence = (
                f"PoC reproduzido: {method.upper()} {url} -> {resp.status_code}\n"
                f"body[:300]: {body_text[:300]}"
            )
            findings.append(
                {"title": title, "severity": sev, "evidence": evidence, "url": url, "verified": True}
            )
            actions.append(f"finding VERIFIED {sev}: {title}")
            return f"VERIFICADO e registrado: [{sev}] {title}"

        actions.append(f"verify_finding falhou: {title} (status={resp.status_code})")
        return (
            f"NAO_REPRODUZIDO: status={resp.status_code} (esperado {expected_status}), "
            f"substring_presente={substring_ok}. Achado '{title}' NAO foi registrado."
        )

    @tool
    async def nuclei_scan(url: str, templates: str = "") -> str:
        """Roda nuclei contra o alvo (requer PH_ENABLE_EXTERNAL_TOOLS=true e o
        binario 'nuclei' no PATH). templates: tag(s) ou caminho opcional passado
        para -t. Scope-guarded, respeita dry_run e o budget de requests."""
        if not settings.enable_external_tools:
            return "DESABILITADO: defina PH_ENABLE_EXTERNAL_TOOLS=true para habilitar nuclei/ffuf/sqlmap"
        violation = await _guard_or_none(url)
        if violation:
            return violation
        cmd = [settings.nuclei_bin, "-u", url, "-silent", "-jsonl"]
        if templates:
            cmd += ["-t", templates]
        if settings.dry_run:
            actions.append(f"DRY nuclei_scan {url}")
            return f"DRY_RUN: would run `{shlex.join(cmd)}`"
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return f"BUDGET: {exc}"
        code, out, err = await _run_subprocess(cmd, settings.external_tool_timeout)
        actions.append(f"nuclei_scan {url} -> exit={code}")
        if code == -1:
            return f"ERRO: {err}"
        return f"nuclei exit={code}\nstdout[:2000]: {out[:2000]}\nstderr[:500]: {err[:500]}"

    @tool
    async def ffuf_scan(url: str, wordlist: str, extra_args: str = "") -> str:
        """Roda ffuf (fuzzing de paths/params) contra o alvo (requer
        PH_ENABLE_EXTERNAL_TOOLS=true e o binario 'ffuf' no PATH). A URL deve
        conter o marcador FUZZ no path ou na query; se nao conter, ele e anexado
        ao final do path. extra_args passa por uma allowlist (-H, -X, -d, -b, -e,
        -t, filtros -mc/-fc/...); -rate vem do escopo. Antes de rodar, palavras
        do wordlist que levariam a URLs fora do escopo sao removidas.
        Scope-guarded, respeita dry_run."""
        if not settings.enable_external_tools:
            return "DESABILITADO: defina PH_ENABLE_EXTERNAL_TOOLS=true para habilitar nuclei/ffuf/sqlmap"
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        if "FUZZ" in authority_of(url) or not url.lower().startswith(("http://", "https://")):
            return "VIOLACAO: o marcador FUZZ so e permitido no path ou na query"
        violation = await _guard_or_none(url)
        if violation:
            return violation
        if not wordlist or wordlist.startswith("-"):
            return f"BLOQUEADO: wordlist invalido: {wordlist!r}"
        try:
            safe_args = sanitize_ffuf_args(
                shlex.split(extra_args) if extra_args else [], scope.max_requests_per_second
            )
        except (ToolArgsDenied, ValueError) as exc:
            return f"BLOQUEADO: {exc}"
        if settings.dry_run:
            cmd = [settings.ffuf_bin, "-u", url, "-w", wordlist, "-of", "json", "-s", *safe_args]
            actions.append(f"DRY ffuf_scan {url}")
            return f"DRY_RUN: would run `{shlex.join(cmd)}` (wordlist filtrado pelo escopo)"
        try:
            filtered, kept, dropped = await asyncio.to_thread(
                _write_filtered_wordlist, wordlist, url, ffuf_extensions(safe_args), scope
            )
        except OSError as exc:
            return f"ERRO: nao foi possivel ler o wordlist: {exc}"
        if filtered is None:
            return f"VIOLACAO: todas as {dropped} palavras do wordlist caem fora do escopo"
        try:
            try:
                budget.request(1)
            except BudgetExhausted as exc:
                return f"BUDGET: {exc}"
            cmd = [settings.ffuf_bin, "-u", url, "-w", filtered, "-of", "json", "-s", *safe_args]
            code, out, err = await _run_subprocess(cmd, settings.external_tool_timeout)
        finally:
            os.unlink(filtered)
        actions.append(f"ffuf_scan {url} -> exit={code} ({dropped} palavras fora do escopo removidas)")
        if code == -1:
            return f"ERRO: {err}"
        return (
            f"ffuf exit={code} ({kept} palavras, {dropped} removidas por escopo)\n"
            f"stdout[:2000]: {out[:2000]}\nstderr[:500]: {err[:500]}"
        )

    @tool
    async def sqlmap_scan(url: str, data: str = "", extra_args: str = "") -> str:
        """Roda sqlmap em modo nao-interativo e de baixo risco contra o alvo
        (requer PH_ENABLE_EXTERNAL_TOOLS=true e o binario 'sqlmap' no PATH).
        --batch, --risk=1 e --level=1 sao sempre forcados; extra_args passa por
        uma allowlist (ex: -p, --technique, --dbms, --cookie, --threads<=4) e
        qualquer outra flag e recusada. Scope-guarded, respeita dry_run."""
        if not settings.enable_external_tools:
            return "DESABILITADO: defina PH_ENABLE_EXTERNAL_TOOLS=true para habilitar nuclei/ffuf/sqlmap"
        violation = await _guard_or_none(url)
        if violation:
            return violation
        try:
            safe_args = sanitize_sqlmap_args(shlex.split(extra_args) if extra_args else [])
        except (ToolArgsDenied, ValueError) as exc:
            return f"BLOQUEADO: {exc}"
        cmd = [settings.sqlmap_bin, "-u", url, *safe_args[: len(SQLMAP_FORCED)]]
        if data:
            cmd += ["--data", data]
        cmd += safe_args[len(SQLMAP_FORCED):]
        if settings.dry_run:
            actions.append(f"DRY sqlmap_scan {url}")
            return f"DRY_RUN: would run `{shlex.join(cmd)}`"
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return f"BUDGET: {exc}"
        code, out, err = await _run_subprocess(cmd, settings.external_tool_timeout)
        actions.append(f"sqlmap_scan {url} -> exit={code}")
        if code == -1:
            return f"ERRO: {err}"
        return f"sqlmap exit={code}\nstdout[:2000]: {out[:2000]}\nstderr[:500]: {err[:500]}"

    @tool
    async def finish(reason: str) -> str:
        """Encerra o loop e dispara o relatorio final. Use quando cobrir o escopo."""
        actions.append(f"finish: {reason}")
        return f"FINISH: {reason}"

    return [
        check_scope,
        http_probe,
        scan_js_bundle,
        analyze_text_for_secrets,
        save_finding,
        verify_finding,
        nuclei_scan,
        ffuf_scan,
        sqlmap_scan,
        finish,
    ]
