from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from rich.console import Console

from .budget import Budget
from .config import Settings, load_scope
from .graph import build_graph, initial_state
from .llm import build_llm

app = typer.Typer(no_args_is_help=True)
console = Console()


def _build(settings: Settings, scope, llm):
    budget = Budget(
        max_steps=settings.max_steps,
        max_requests=settings.max_total_requests,
        max_tokens=settings.max_tokens_budget,
    )
    findings: list = []
    actions: list = []
    graph = build_graph(settings, scope, llm, budget, findings, actions)
    return graph, budget, findings, actions


@app.command()
def run(
    target: str = typer.Option(..., help="URL alvo"),
    scope_file: Path = typer.Option(..., help="JSON do TargetScope"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    output: Path | None = typer.Option(None, help="salvar relatorio em arquivo"),
) -> None:
    settings = Settings(dry_run=dry_run)
    scope = load_scope(scope_file)
    if settings.require_authorization and not scope.authorized_by:
        raise typer.BadParameter("scope.authorized_by e obrigatorio")
    llm = build_llm(settings)
    graph, budget, findings, actions = _build(settings, scope, llm)
    final = asyncio.run(graph.ainvoke(initial_state(target)))
    _emit(final, output)


@app.command()
def demo(dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run")) -> None:
    """Smoke test com LLM fake: valida o loop ReAct sem custo de API."""
    settings = Settings(dry_run=dry_run)
    scope = load_scope(Path("scope.json"))
    fake = FakeToolCallingLLM(
        tool_call_script=[
            [{"name": "check_scope", "args": {"url": "http://localhost:3000/"}, "id": "c1"}],
            [{"name": "http_probe", "args": {"url": "http://localhost:3000/"}, "id": "c2"}],
            [
                {
                    "name": "save_finding",
                    "args": {
                        "title": "demo finding",
                        "severity": "LOW",
                        "evidence": "demo",
                        "url": "http://localhost:3000/",
                    },
                    "id": "c3",
                }
            ],
            [{"name": "finish", "args": {"reason": "demo concluido"}, "id": "c4"}],
        ]
    )
    graph, budget, findings, actions = _build(settings, scope, fake)
    final = asyncio.run(graph.ainvoke(initial_state("http://localhost:3000/")))
    _emit(final, None)


@app.command()
def check_scope(target: str, scope_file: Path) -> None:
    from .scope_guard import ScopeViolation, Target, check_target

    scope = load_scope(scope_file)
    try:
        check_target(Target(target), scope, 0, 500)
        # style= colors the whole line without parsing the interpolated text
        # as markup — a target/path containing "[" or "]" must never be
        # misread as a style tag (and must never silently vanish from output).
        console.print(f"OK {target} dentro do escopo", style="green")
    except ScopeViolation as exc:
        console.print(f"VIOLACAO {exc}", style="red")
        raise typer.Exit(1)


def _emit(final: dict, output: Path | None) -> None:
    report = final.get("final_report", "")
    # markup=False: the report embeds LLM-authored finding titles/evidence
    # and tags like "[VERIFIED]"/"[unverified]" — rich would otherwise parse
    # those brackets as style markup and silently drop or corrupt them.
    console.print(report, markup=False)
    console.print_json(json.dumps(final.get("budget_snapshot", {})))
    if output:
        output.write_text(report, encoding="utf-8")
        console.print(f"relatorio salvo em {output}", style="green")


class FakeToolCallingLLM(FakeListChatModel):
    """LLM fake que emite AIMessage com tool_calls segundo um script, para a demo.

    FakeListChatModel sozinho so devolve strings; aqui sobrescrevemos a geracao
    para produzir tool_calls reais e exercitar o loop ReAct sem custo de API.
    """

    tool_call_script: list = []
    _cursor: int = 0

    def __init__(self, tool_call_script: list, **kwargs):
        super().__init__(responses=[""] * (len(tool_call_script) + 1), **kwargs)
        object.__setattr__(self, "tool_call_script", tool_call_script)
        object.__setattr__(self, "_cursor", 0)

    def bind_tools(self, tools, **kwargs):
        return self

    def _next_tool_calls(self):
        from langchain_core.messages import AIMessage

        idx = self._cursor
        object.__setattr__(self, "_cursor", idx + 1)
        if idx < len(self.tool_call_script):
            return AIMessage(content="", tool_calls=self.tool_call_script[idx])
        return AIMessage(content="loop concluido")

    async def ainvoke(self, *args, **kwargs):
        return self._next_tool_calls()

    def invoke(self, *args, **kwargs):
        return self._next_tool_calls()
