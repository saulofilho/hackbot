from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from .config import TargetScope


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


def _host_in_cidrs(host: str, cidrs: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)


def check_target(target: Target, scope: TargetScope, request_count: int, settings_max: int) -> None:
    if request_count >= settings_max:
        raise ScopeViolation(f"kill switch: {request_count} requisicoes >= maximo {settings_max}")

    host = target.host
    if not host:
        raise ScopeViolation(f"URL sem host: {target.url}")

    host_ok = any(fnmatch(host, pattern) for pattern in scope.allowed_hosts)
    host_ok = host_ok or _host_in_cidrs(host, scope.allowed_cidrs)
    if not host_ok:
        raise ScopeViolation(f"host '{host}' fora do escopo autorizado")

    path = target.path
    if not any(fnmatch(path, p) for p in scope.allowed_paths):
        raise ScopeViolation(f"path '{path}' fora do escopo autorizado")

    for excl in scope.exclude_paths:
        if fnmatch(path, excl):
            raise ScopeViolation(f"path '{path}' explicitamente excluido: {excl}")
