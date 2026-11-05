import pytest
from hackbot.config import TargetScope
from hackbot.scope_guard import ScopeViolation, Target, check_target


def _scope(**kw):
    base = dict(allowed_hosts=["localhost", "*.lab"], allowed_paths=["/*"], authorized_by="x")
    base.update(kw)
    return TargetScope(**base)


def test_blocks_out_of_scope_host():
    with pytest.raises(ScopeViolation):
        check_target(Target("http://evil.com/"), _scope(), 0, 100)


def test_allows_wildcard_subdomain():
    check_target(Target("http://juice-shop.lab/api"), _scope(), 0, 100)


def test_blocks_excluded_path():
    with pytest.raises(ScopeViolation):
        check_target(Target("http://localhost/logout"), _scope(), 0, 100)


def test_kill_switch():
    with pytest.raises(ScopeViolation):
        check_target(Target("http://localhost/"), _scope(), 100, 100)


def test_wildcard_host_rejected():
    with pytest.raises(Exception):
        TargetScope(allowed_hosts=["*"], authorized_by="x")
