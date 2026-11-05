from __future__ import annotations

import operator
from typing import Annotated, Any

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class AttackState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    findings: Annotated[list[dict[str, Any]], operator.add]
    actions_taken: Annotated[list[str], operator.add]
    target_url: str
    finished: bool
    finish_reason: str
    budget_snapshot: dict
    final_report: str
