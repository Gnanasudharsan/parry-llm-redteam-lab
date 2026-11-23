# ADR 0003: Lab targets share code with their hardened twins, behind explicit controls

- Status: accepted
- Date: 2026-11-23

## Context

Phase 1 needs three deliberately vulnerable LLM apps (RAG app, tool-using agent, MCP server),
each with a hardened twin, so later phases can measure how much each defense actually helps.
Two separate codebases per target would drift apart: a measured difference could come from
some incidental change rather than the defense under test.

## Decision

1. **One codebase per target, two profiles.** `PROFILE=vulnerable` turns every control off,
   `PROFILE=hardened` turns every control on. Each control is a named flag
   (`targets/lab/profile.py`) that can also be toggled alone (`HARDEN_<FLAG>=0|1`), so Phase 3
   can ablate one defense at a time.
2. **Controls are ordinary engineering, not magic prompts:** retrieval ACLs, path sandboxing,
   spotlighting untrusted content, an instruction-hierarchy system prompt, output redaction of
   known secrets, markdown sanitization, egress allowlists, and a tool permission policy.
3. **Benign proof of impact.** Each target derives canaries and fake secrets from `LAB_SEED`
   and the target name (HMAC-SHA256), so Parry's judges can recompute them without reading the
   target. Tools are mocks over in-memory state: `send_email`, `transfer_funds` and
   `delete_file` only record an event.
4. **Network isolation is the real egress control.** Targets and the mock web/exfiltration
   service sit on an `internal: true` Docker network with no route to the internet. A single
   nginx gateway joins both networks: it publishes the target ports on `127.0.0.1` only and
   forwards the model API to Ollama on the host. The lab's fictional domains
   (`docs.harborview.test`, `attacker.test`, `backup.harborview.test`) are network aliases of the
   mock web service, so an "exfiltration" can only ever reach a recorder.
5. **Simulated rendering.** Many real leaks happen when a chat UI renders a markdown image whose
   URL carries data. The apps emulate that UI: in the vulnerable profile every image URL in the
   answer is fetched (and lands in the recorder); the hardened profile strips non-allowlisted
   links and images before anything is fetched.
6. **Local models only by default.** `qwen2.5:7b-instruct` (chat and tool calling) and
   `nomic-embed-text` (embeddings) through Ollama, temperature 0 with a fixed seed.

## Consequences

- A hardened twin is credited only with the improvement measured on the same attacks, seeds and
  model as its vulnerable twin.
- Small local models are weaker than hosted ones; results are reported per model and are not
  claims about other models.
- Ollama runs on the host (Metal GPU) rather than in Docker, so the gateway is the one lab
  container with a route off the internal network, and only to the Ollama port.
