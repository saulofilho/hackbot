from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class TargetScope(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["/logout", "/admin/delete", "/billing/charge"]
    )
    max_requests_per_second: float = 5.0
    authorized_by: str = ""
    authorization_ref: str = ""

    @field_validator("allowed_hosts")
    @classmethod
    def _no_wildcards(cls, v: list[str]) -> list[str]:
        if any(h.strip() == "*" for h in v):
            raise ValueError("wildcard '*' nao permitido no escopo")
        return v


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="PH_", extra="ignore")

    llm_provider: Literal["openai", "anthropic"] = "openai"
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    llm_temperature: float = 0.2

    dry_run: bool = True
    require_authorization: bool = True
    max_total_requests: int = 200
    max_steps: int = 20
    max_tokens_budget: int = 200_000

    workspace_dir: Path = Path("./.hackbot")
    user_agent: str = "hackbot/0.1 (+authorized-pentest)"

    # External scanner tools (nuclei/ffuf/sqlmap). Off by default: a second,
    # independent gate on top of dry_run/scope_guard — these shell out to real
    # binaries and must be explicitly opted into, never inferred by the agent.
    enable_external_tools: bool = False
    external_tool_timeout: float = 60.0
    nuclei_bin: str = "nuclei"
    ffuf_bin: str = "ffuf"
    sqlmap_bin: str = "sqlmap"


def load_scope(path: Path) -> TargetScope:
    return TargetScope.model_validate_json(path.read_text())
