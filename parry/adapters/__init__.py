"""Target adapters: one small class per way of talking to a system under test.

Chat-style targets implement `ChatAdapter.chat`; MCP servers implement `McpAdapter`.
`make_adapter` picks the class from a target's `kind`.
"""

from parry.adapters.base import ChatAdapter, McpAdapter, Reply, make_adapter

__all__ = ["ChatAdapter", "McpAdapter", "Reply", "make_adapter"]
