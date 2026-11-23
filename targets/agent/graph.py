"""The agent loop as a LangGraph graph: model -> (tool calls?) -> tools -> model -> ... -> end."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

MAX_STEPS = 8  # model turns per request; keeps a hijacked agent from looping forever


def build_graph(
    model: BaseChatModel, tools: list[BaseTool], system_prompt: str
) -> CompiledStateGraph[Any, Any, Any, Any]:
    bound = model.bind_tools(tools)
    by_name = {t.name: t for t in tools}

    def call_model(state: MessagesState) -> dict[str, list[BaseMessage]]:
        reply = bound.invoke([SystemMessage(system_prompt), *state["messages"]])
        return {"messages": [reply]}

    def call_tools(state: MessagesState) -> dict[str, list[BaseMessage]]:
        last = state["messages"][-1]
        assert isinstance(last, AIMessage)  # noqa: S101 - routing guarantees this
        out: list[BaseMessage] = []
        for call in last.tool_calls:
            tool = by_name.get(call["name"])
            if tool is None:
                result = f"Unknown tool {call['name']!r}."
            else:
                try:
                    result = str(tool.invoke(call["args"]))
                except Exception as exc:  # bad arguments from the model
                    result = f"Tool error: {exc}"
            out.append(ToolMessage(result, tool_call_id=call["id"] or call["name"]))
        return {"messages": out}

    def route(state: MessagesState) -> str:
        last = state["messages"][-1]
        steps = sum(isinstance(m, AIMessage) for m in state["messages"])
        if isinstance(last, AIMessage) and last.tool_calls and steps < MAX_STEPS:
            return "tools"
        return END

    graph = StateGraph(MessagesState)
    graph.add_node("model", call_model)
    graph.add_node("tools", call_tools)
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", route, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    return graph.compile()
