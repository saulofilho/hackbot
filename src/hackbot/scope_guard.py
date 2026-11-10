"""Scope guard: o portao rigido antes de qualquer I/O de rede.

Tres camadas, todas fail-closed:

1. `check_target`: valida a URL (parser do httpx, o mesmo que envia a
   requisicao), host, path normalizado e exclusoes.
2. `resolve_target`: resolve o host e valida *cada* IP retornado. Metadados de
   nuvem sao sempre negados; redes internas so passam se autorizadas no escopo.
3. Quem envia conecta no IP validado (DNS pinning), mantendo Host/SNI do nome
   original, para que uma segunda resolucao (DNS rebinding) nao mude o destino.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from urllib.parse import unquote, urlparse

import httpx

from .config import TargetScope

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str, int], Awaitable[list[IPAddress]]]

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LENGTH = 8192

# Nunca liberados, nem por allowed_cidrs.
ALWAYS_DENIED: tuple[Network, ...] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "169.254.169.254/32",  # metadados AWS/GCP/Azure/OpenStack
        "169.254.170.2/32",  # credenciais de task do ECS
        "100.100.100.200/32",  # metadados Alibaba Cloud
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "fd00:ec2::254/128",  # metadados AWS (IPv6)
        "ff00::/8",
    )
)

# Redes internas: bloqueadas a menos que o escopo as autorize explicitamente.
INTERNAL: tuple[Network, ...] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_FORBIDDEN_URL_CHARS = re.compile(r"[\s\\\x00-\x1f\x7f]")
_AUTHORITY = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]*)")


class ScopeViolation(RuntimeError):
    """Violacao de escopo: hard-fail, mata a sessao."""


@dataclass(frozen=True)
class Target:
    url: str

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"


@dataclass(frozen=True)
class CheckedTarget:
    """URL que ja passou por `check_target`."""

    url: httpx.URL
    scheme: str
    host: str
    port: int
    path: str
    host_ip: IPAddress | None

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def normalize_path(raw_path: str) -> str:
    """Normaliza o path antes de comparar com o escopo.

    Decodifica %XX uma vez, remove parametros de matriz (`;x`), resolve `.`/`..`
    e colapsa barras repetidas. Codificacao dupla e `..` acima da raiz sao
    rejeitados: servidores diferentes interpretam isso de formas diferentes.
    """
    path = raw_path.split("?", 1)[0].split("#", 1)[0] or "/"
    decoded = unquote(path, errors="replace")
    if _PERCENT_ESCAPE.search(decoded):
        raise ScopeViolation(f"codificacao dupla no path: {raw_path!r}")
    if _FORBIDDEN_URL_CHARS.search(decoded):
        raise ScopeViolation(f"caractere proibido no path: {raw_path!r}")
    segments: list[str] = []
    for raw_segment in decoded.split("/"):
        segment = raw_segment.split(";", 1)[0]
        if segment in ("", "."):
            continue
        if segment == "..":
            if not segments:
                raise ScopeViolation(f"path sobe acima da raiz: {raw_path!r}")
            segments.pop()
            continue
        segments.append(segment)
    normalized = "/" + "/".join(segments)
    if segments and decoded.endswith("/"):
        normalized += "/"
    return normalized


def authority_of(url: str) -> str:
    """Trecho `user@host:port` da URL, como texto bruto ('' se nao houver)."""
    match = _AUTHORITY.match(url)
    return match.group(1) if match else ""


def _excluded_by(path: str, patterns: list[str]) -> str | None:
    """Exclusao sem diferenciar maiusculas e cobrindo tudo abaixo do path
    (`/logout` tambem bloqueia `/logout/`, `/Logout` e `/logout/x`)."""
    lowered = path.lower()
    trimmed = lowered.rstrip("/") or "/"
    for pattern in patterns:
        p = pattern.lower().rstrip("/") or "/"
        if (
            fnmatchcase(lowered, p)
            or fnmatchcase(trimmed, p)
            or fnmatchcase(lowered, p.rstrip("/") + "/*")
        ):
            return pattern
    return None


def _host_allowed(scope: TargetScope, host: str, ip: IPAddress | None) -> bool:
    patterns = [_normalize_host(p) for p in scope.allowed_hosts]
    if ip is not None:
        return str(ip) in {str(_parse_ip(p)) for p in patterns if _parse_ip(p)} or any(
            ip in ipaddress.ip_network(c, strict=False) for c in scope.allowed_cidrs
        )
    return any(fnmatchcase(host, p) for p in patterns)


def check_target(
    target: Target, scope: TargetScope, request_count: int, settings_max: int
) -> CheckedTarget:
    """Valida a URL contra o escopo (sem I/O). Levanta `ScopeViolation`."""
    if request_count >= settings_max:
        raise ScopeViolation(f"kill switch: {request_count} requisicoes >= maximo {settings_max}")

    text = target.url
    if len(text) > MAX_URL_LENGTH:
        raise ScopeViolation("URL longa demais")
    if _FORBIDDEN_URL_CHARS.search(text):
        raise ScopeViolation(f"caractere proibido na URL (barra invertida/espaco/controle): {text!r}")
    try:
        parsed = httpx.URL(text)
    except httpx.InvalidURL as exc:
        raise ScopeViolation(f"URL invalida: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ScopeViolation(f"esquema '{scheme}' nao permitido")
    if parsed.userinfo or "@" in authority_of(text):
        raise ScopeViolation("URL com credenciais embutidas (user@host) nao e permitida")

    host = _normalize_host(parsed.raw_host.decode("ascii", errors="replace"))
    if not host:
        raise ScopeViolation(f"URL sem host: {text}")
    ip = _parse_ip(host)
    if ip is not None:
        host = str(ip)
    if not _host_allowed(scope, host, ip):
        raise ScopeViolation(f"host '{host}' fora do escopo autorizado")

    path = normalize_path(parsed.raw_path.decode("ascii", errors="replace"))
    if not any(fnmatchcase(path, p) for p in scope.allowed_paths):
        raise ScopeViolation(f"path '{path}' fora do escopo autorizado")
    excluded = _excluded_by(path, scope.exclude_paths)
    if excluded:
        raise ScopeViolation(f"path '{path}' explicitamente excluido: {excluded}")

    port = parsed.port or DEFAULT_PORTS[scheme]
    return CheckedTarget(url=parsed, scheme=scheme, host=host, port=port, path=path, host_ip=ip)


# --------------------------------------------------------------------------
# Politica de IP (SSRF / DNS rebinding)
# --------------------------------------------------------------------------

def canonical_ip(ip: IPAddress) -> IPAddress:
    """Extrai o IPv4 embutido em formas IPv6 (mapeado, NAT64, 6to4)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def check_ip(ip: IPAddress, host: str, scope: TargetScope) -> None:
    """Valida um IP resolvido. Metadados de nuvem nunca passam; redes internas
    so passam se listadas em `allowed_cidrs`, se o IP literal estiver em
    `allowed_hosts`, ou se o host for `localhost` resolvendo para loopback."""
    explicit_ips = {_parse_ip(_normalize_host(h)) for h in scope.allowed_hosts} - {None}
    cidrs = [ipaddress.ip_network(c, strict=False) for c in scope.allowed_cidrs]
    for candidate in {ip, canonical_ip(ip)}:
        for net in ALWAYS_DENIED:
            if candidate in net:
                raise ScopeViolation(f"destino {ip} proibido ({net})")
        for net in INTERNAL:
            if candidate not in net:
                continue
            authorized = (
                candidate in explicit_ips
                or any(candidate in c for c in cidrs)
                or (host == "localhost" and candidate.is_loopback)
            )
            if not authorized:
                raise ScopeViolation(
                    f"'{host}' resolve para {ip}, rede interna ({net}); "
                    "liste a faixa em allowed_cidrs para autorizar"
                )


async def system_resolver(host: str, port: int) -> list[IPAddress]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: list[IPAddress] = []
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if ip not in ips:
            ips.append(ip)
    return ips


async def resolve_target(
    checked: CheckedTarget, scope: TargetScope, resolver: Resolver = system_resolver
) -> list[IPAddress]:
    """Resolve o host e valida todos os IPs. Se so um passasse, a escolha do IP
    na conexao decidiria se o bloqueio vale."""
    if checked.host_ip is not None:
        ips = [checked.host_ip]
    else:
        try:
            ips = await resolver(checked.host, checked.port)
        except OSError as exc:
            raise ScopeViolation(f"falha ao resolver {checked.host}: {exc}") from exc
    if not ips:
        raise ScopeViolation(f"{checked.host} nao resolveu para nenhum IP")
    for ip in ips:
        check_ip(ip, checked.host, scope)
    return ips
