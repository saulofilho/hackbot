from __future__ import annotations

import asyncio
import re
import shlex
from typing import Any

import httpx
from langchain_core.tools import tool

from .budget import Budget, BudgetExhausted
from .config import Settings, TargetScope
from .scope_guard import ScopeViolation, Target, check_target

SECRET_PATTERNS = {
    "aws_akid": re.compile(r"AKIA[0-9A-Z]{16}"),
    "openai": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# sqlmap flags that can turn a scan into code execution, file access, or data
# exfiltration beyond the query itself. Always rejected, regardless of
# enable_external_tools — this is a hard denylist, not a default.
SQLMAP_DENYLIST = (
    "--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay", "--os-bof",
    "--priv-esc", "--file-write", "--file-dest", "--file-read",
    "--dump-all", "--passwords", "--privileges", "--all",
    "--reg-add", "--reg-del", "--reg-read", "--registry-read",
    "--registry-write", "--registry-process", "--sql-shell", "--eval",
)


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
) -> list:
    """Factory: cria tools com closures sobre settings/scope/budget/coletores."""

    async def _guard_or_none(url: str) -> str | None:
        """Shared scope check used by every network-facing tool. Returns an
        error string on violation, or None when the URL is clear to proceed.
        """
        try:
            check_target(Target(url), scope, budget.requests, settings.max_total_requests)
            return None
        except ScopeViolation as exc:
            return f"VIOLACAO: {exc}"

    async def _do_http_request(
        url: str, method: str, headers: dict[str, str] | None, body: str
    ) -> tuple[bool, str, httpx.Response | None]:
        """Core of http_probe, factored out so verify_finding can replay the
        exact same guarded/budgeted/rate-limited request path.
        Returns (ok, message_or_dry_run_text, response_or_None).
        """
        violation = await _guard_or_none(url)
        if violation:
            return False, violation, None
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}:
            return False, f"metodo nao permitido: {method}", None
        if settings.dry_run:
            actions.append(f"DRY http_probe {method} {url}")
            return False, f"DRY_RUN: would {method} {url} (body={len(body)}B)", None
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return False, f"BUDGET: {exc}", None
        delay = 1.0 / max(scope.max_requests_per_second, 0.1)
        h = {"User-Agent": settings.user_agent}
        if headers:
            h.update(headers)
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.request(method, url, headers=h, content=body or None)
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
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return f"BUDGET: {exc}"
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers={"User-Agent": settings.user_agent})
            except httpx.HTTPError as exc:
                return f"ERRO: {exc}"
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
        conter o marcador FUZZ; se nao conter, ele e anexado ao final do path.
        Scope-guarded (checado contra a URL com FUZZ), respeita dry_run."""
        if not settings.enable_external_tools:
            return "DESABILITADO: defina PH_ENABLE_EXTERNAL_TOOLS=true para habilitar nuclei/ffuf/sqlmap"
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        violation = await _guard_or_none(url)
        if violation:
            return violation
        cmd = [settings.ffuf_bin, "-u", url, "-w", wordlist, "-of", "json", "-s"]
        if extra_args:
            cmd += shlex.split(extra_args)
        if settings.dry_run:
            actions.append(f"DRY ffuf_scan {url}")
            return f"DRY_RUN: would run `{shlex.join(cmd)}`"
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return f"BUDGET: {exc}"
        code, out, err = await _run_subprocess(cmd, settings.external_tool_timeout)
        actions.append(f"ffuf_scan {url} -> exit={code}")
        if code == -1:
            return f"ERRO: {err}"
        return f"ffuf exit={code}\nstdout[:2000]: {out[:2000]}\nstderr[:500]: {err[:500]}"

    @tool
    async def sqlmap_scan(url: str, data: str = "", extra_args: str = "") -> str:
        """Roda sqlmap em modo nao-interativo e de baixo risco contra o alvo
        (requer PH_ENABLE_EXTERNAL_TOOLS=true e o binario 'sqlmap' no PATH).
        --batch, --risk=1 e --level=1 sao sempre forcados; flags perigosas
        (os-shell, file-write/read, dump-all, etc.) sao sempre bloqueadas,
        mesmo se pedidas em extra_args. Scope-guarded, respeita dry_run."""
        if not settings.enable_external_tools:
            return "DESABILITADO: defina PH_ENABLE_EXTERNAL_TOOLS=true para habilitar nuclei/ffuf/sqlmap"
        violation = await _guard_or_none(url)
        if violation:
            return violation
        extra_tokens = shlex.split(extra_args) if extra_args else []
        for tok in extra_tokens:
            low = tok.lower().split("=")[0]
            if low in SQLMAP_DENYLIST:
                return f"BLOQUEADO: flag perigosa '{tok}' nao permitida em sqlmap_scan"
        # strip any attempt to override risk/level; we fix them ourselves
        extra_tokens = [
            t for t in extra_tokens
            if not t.lower().startswith(("--risk", "--level"))
        ]
        cmd = [settings.sqlmap_bin, "-u", url, "--batch", "--risk=1", "--level=1"]
        if data:
            cmd += ["--data", data]
        cmd += extra_tokens
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
