# Lab targets

Deliberately vulnerable LLM apps for learning and benchmarking, each with a hardened twin
built from the same code. Full guide: [docs/lab.md](../docs/lab.md).

| Target | Code | Vulnerable | Hardened |
|---|---|---|---|
| RAG customer assistant (FastAPI + numpy vector store + Ollama) | `rag/` | `vuln-rag` :8101 | `hard-rag` :8102 |
| Tool-using ops agent (LangGraph; mock bank, email, files, orders, web) | `agent/` | `vuln-agent` :8111 | `hard-agent` :8112 |
| Workspace MCP server (official MCP Python SDK, streamable HTTP) | `mcp_server/` | `vuln-mcp` :8121 | `hard-mcp` :8122 |
| Mock web + exfiltration recorder | `mockweb/` | `mockweb` :8199 | |

Shared pieces live in `lab/`: canaries and fake secrets (`canary.py`), hardening profiles
(`profile.py`), hardening helpers (`guard.py`), recorded egress (`egress.py`), the event log
and the token-guarded admin API.

Nothing in here touches the real network, real files or real money. Mock tools only change
in-memory state and record events, and the lab network has no route to the internet.
