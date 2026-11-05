from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from .budget import Budget, BudgetExhausted
from .config import Settings, TargetScope
from .prompts import SYSTEM_PROMPT
from .state import AttackState
from .tools import make_tools


def build_graph(
    settings: Settings,
    scope: TargetScope,
    llm: Any,
    budget: Budget,
    findings: list[dict[str, Any]],
    actions: list[str],
):
    tools = make_tools(settings, scope, budget, findings, actions)
    llm_with_tools = llm.bind_tools(tools)
    tool_node = ToolNode(tools)

    async def agent_node(state: AttackState) -> dict:
        if budget.exhausted_reason:
            return {
                "messages": [AIMessage(content=f"Budget esgotado: {budget.exhausted_reason}")],
                "budget_snapshot": budget.snapshot(),
            }
        try:
            budget.step()
        except BudgetExhausted:
            return {
                "messages": [AIMessage(content=f"Budget esgotado: {budget.exhausted_reason}")],
                "budget_snapshot": budget.snapshot(),
            }
        resp = await llm_with_tools.ainvoke(state["messages"])
        usage = getattr(resp, "usage_metadata", None) or {}
        try:
            budget.add_tokens(int(usage.get("total_tokens", 0)))
        except BudgetExhausted:
            pass
        return {"messages": [resp], "budget_snapshot": budget.snapshot()}

    def route(state: AttackState) -> str:
        if budget.exhausted_reason:
            return "report"
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            if any(tc["name"] == "finish" for tc in last.tool_calls):
                return "tools_finish"
            return "tools"
        return "report"

    async def report_node(state: AttackState) -> dict:
        lines = ["# Relatorio de Pentest (hackbot)", ""]
        lines.append(f"**Alvo:** {state.get('target_url', '?')}")
        lines.append(f"**Budget:** {budget.snapshot()}")
        lines.append(f"**Achados:** {len(findings)}")
        lines.append("")
        lines.append("## Achados")
        if not findings:
            lines.append("_Nenhum achado registrado._")
        for f in findings:
            lines.append(f"- **[{f['severity']}]** {f['title']} — {f['url']}")
            lines.append(f"  - evidencia: `{f['evidence'][:300]}`")
        lines.append("")
        lines.append("## Acoes executadas")
        for a in actions:
            lines.append(f"- {a}")
        return {"final_report": "\n".join(lines), "finished": True}

    g = StateGraph(AttackState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.add_node("tools_finish", tool_node)
    g.add_node("report", report_node)

    g.set_entry_point("agent")
    g.add_conditional_edges(
        "agent",
        route,
        {"tools": "tools", "tools_finish": "tools_finish", "report": "report"},
    )
    g.add_edge("tools", "agent")
    g.add_edge("tools_finish", "report")
    g.add_edge("report", END)
    return g.compile()


def initial_state(target_url: str) -> AttackState:
    return {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Alvo autorizado: {target_url}\n"
                    "Comece checando o escopo, faca recon leve (headers, robots, JS), "
                    "registre achados e chame finish quando terminar."
                )
            ),
        ],
        "target_url": target_url,
        "findings": [],
        "actions_taken": [],
        "finished": False,
        "finish_reason": "",
    }
