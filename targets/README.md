# Lab targets

Deliberately vulnerable LLM apps for learning and benchmarking, each with a hardened twin.
Built in Phase 1 and run with `make targets-up` (Docker Compose, isolated network).

| Target | Vulnerable | Hardened twin |
|---|---|---|
| RAG app (FastAPI + small vector store) | `vuln_rag` | `hard_rag` |
| Tool-using agent (LangGraph; mock `send_email`, `delete_file`, `transfer_funds` that only log) | `vuln_agent` | `hard_agent` |
| MCP server | `vuln_mcp` | `hard_mcp` |

Every target holds a canary in its system prompt, fake secrets, and points at a local mock
exfiltration endpoint. Nothing in here touches the real network, real files or real money.
