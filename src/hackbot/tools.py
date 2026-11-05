from __future__ import annotations

import re
import time
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


def make_tools(
    settings: Settings,
    scope: TargetScope,
    budget: Budget,
    findings: list[dict[str, Any]],
    actions: list[str],
) -> list:
    """Factory: cria tools com closures sobre settings/scope/budget/coletores."""

    @tool
    async def check_scope(url: str) -> str:
        """Valida se a URL esta dentro do escopo autorizado. Use ANTES de qualquer requisicao."""
        try:
            check_target(Target(url), scope, budget.requests, settings.max_total_requests)
            return f"OK: {url} dentro do escopo"
        except ScopeViolation as exc:
            return f"VIOLACAO: {exc}"

    @tool
    async def http_probe(
        url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str = ""
    ) -> str:
        """Faz requisicao HTTP ao alvo. Respeita scope, rate limit e dry_run."""
        try:
            check_target(Target(url), scope, budget.requests, settings.max_total_requests)
        except ScopeViolation as exc:
            return f"VIOLACAO: {exc}"
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}:
            return f"metodo nao permitido: {method}"
        if settings.dry_run:
            actions.append(f"DRY http_probe {method} {url}")
            return f"DRY_RUN: would {method} {url} (body={len(body)}B)"
        try:
            budget.request(1)
        except BudgetExhausted as exc:
            return f"BUDGET: {exc}"
        delay = 1.0 / max(scope.max_requests_per_second, 0.1)
        h = {"User-Agent": settings.user_agent}
        if headers:
            h.update(headers)
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.request(method, url, headers=h, content=body or None)
            except httpx.HTTPError as exc:
                actions.append(f"ERR http_probe {method} {url}: {exc}")
                return f"ERRO: {exc}"
        time.sleep(delay)
        snippet = resp.text[:500].replace("\n", " ")
        actions.append(f"http_probe {method} {url} -> {resp.status_code}")
        return (
            f"{method} {url} -> {resp.status_code}\n"
            f"headers: {dict(list(resp.headers.items())[:10])}\n"
            f"body[:500]: {snippet}"
        )

    @tool
    async def scan_js_bundle(url: str) -> str:
        """Baixa um arquivo JS e procura segredos, cartoes e padroes de exfiltracao."""
        try:
            check_target(Target(url), scope, budget.requests, settings.max_total_requests)
        except ScopeViolation as exc:
            return f"VIOLACAO: {exc}"
        if settings.dry_run:
            actions.append(f"DRY scan_js_bundle {url}")
            return f"DRY_RUN: would download and scan {url}"
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
        hits: list[str] = []
        for name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(text):
                hits.append(f"{name}: {m.group(0)[:40]}...")
        suspicious = []
        for kw in ("eval(", "atob(", "XMLHttpRequest", "fetch(", "document.cookie"):
            if kw in text:
                suspicious.append(kw)
        actions.append(f"scan_js_bundle {url} -> {len(hits)} secrets, {len(suspicious)} suspicious")
        return (
            f"JS {url} ({len(text)}B) status={resp.status_code}\n"
            f"segredos ({len(hits)}): {hits[:20]}\n"
            f"padroes suspeitos: {suspicious}"
        )

    @tool
    async def analyze_text_for_secrets(text: str) -> str:
        """Analisa um texto colado em busca de segredos (regex)."""
        hits = []
        for name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(text):
                hits.append(f"{name}: {m.group(0)[:40]}...")
        return f"encontrados {len(hits)}: {hits[:20]}"

    @tool
    async def save_finding(title: str, severity: str, evidence: str, url: str = "") -> str:
        """Registra um achado. Severidade: CRITICAL/HIGH/MEDIUM/LOW/INFO."""
        sev = severity.upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            sev = "INFO"
        findings.append(
            {"title": title, "severity": sev, "evidence": evidence[:2000], "url": url}
        )
        actions.append(f"finding {sev}: {title}")
        return f"registrado: [{sev}] {title}"

    @tool
    async def finish(reason: str) -> str:
        """Encerra o loop e dispara o relatorio final. Use quando cobrir o escopo."""
        actions.append(f"finish: {reason}")
        return f"FINISH: {reason}"

    return [check_scope, http_probe, scan_js_bundle, analyze_text_for_secrets, save_finding, finish]
