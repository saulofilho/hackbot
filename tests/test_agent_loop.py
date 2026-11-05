"""Valida o loop ReAct ponta-a-ponta com LLM fake, sem chamar a rede real."""
import asyncio

from hackbot.budget import Budget
from hackbot.config import Settings, TargetScope
from hackbot.graph import build_graph, initial_state


def test_loop_runs_and_reports(monkeypatch, tmp_path):
    # Este teste valida o grafo com um LLM fake simples que nao chama tools:
    # ele deve cair direto no report node sem estourar.
    from langchain_core.messages import AIMessage

    class NoToolLLM:
        async def ainvoke(self, messages):
            return AIMessage(content="nada a fazer")

        def bind_tools(self, tools, **kwargs):
            return self

    scope = TargetScope(allowed_hosts=["localhost"], authorized_by="x")
    settings = Settings(dry_run=True, require_authorization=False, max_steps=3)
    budget = Budget(max_steps=3, max_requests=10, max_tokens=1000)
    findings: list = []
    actions: list = []
    graph = build_graph(settings, scope, NoToolLLM(), budget, findings, actions)
    final = asyncio.run(graph.ainvoke(initial_state("http://localhost:3000/")))
    assert "Relatorio" in final["final_report"]
    assert final["finished"] is True


def test_loop_runs_full_react_cycle():
    """LLM fake que chama tools em sequencia: check_scope -> http_probe -> save_finding -> finish."""
    from langchain_core.messages import AIMessage

    class ScriptedLLM:
        def __init__(self):
            self.script = [
                [{"name": "check_scope", "args": {"url": "http://localhost:3000/"}, "id": "c1"}],
                [{"name": "http_probe", "args": {"url": "http://localhost:3000/"}, "id": "c2"}],
                [
                    {
                        "name": "save_finding",
                        "args": {
                            "title": "demo",
                            "severity": "LOW",
                            "evidence": "ev",
                            "url": "http://localhost:3000/",
                        },
                        "id": "c3",
                    }
                ],
                [{"name": "finish", "args": {"reason": "done"}, "id": "c4"}],
            ]
            self.i = 0

        async def ainvoke(self, messages):
            if self.i < len(self.script):
                calls = self.script[self.i]
                self.i += 1
                return AIMessage(content="", tool_calls=calls)
            return AIMessage(content="fim")

        def bind_tools(self, tools, **kwargs):
            return self

    scope = TargetScope(allowed_hosts=["localhost"], authorized_by="x")
    settings = Settings(dry_run=True, require_authorization=False, max_steps=20)
    budget = Budget(max_steps=20, max_requests=50, max_tokens=100000)
    findings: list = []
    actions: list = []
    graph = build_graph(settings, scope, ScriptedLLM(), budget, findings, actions)
    final = asyncio.run(graph.ainvoke(initial_state("http://localhost:3000/")))
    assert final["finished"] is True
    assert len(findings) == 1
    assert any("finish" in a for a in actions)
