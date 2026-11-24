# Phase 3 results

| folder | what | reported? |
|---|---|---|
| `phase3-matrix/` | the final defense matrix: 42 cells (vuln-mcp 13, vuln-rag 14, vuln-agent 15) | yes |
| `phase3-spotchecks/` | `none` and `pi_classifier` rerun on the rebuilt lab: the bridge between original and rerun cells (all six pass) | as evidence only |
| `archive/phase3-original-superseded/` | the 9 original cells replaced by reruns: `output_validator` and `hardened+guards` (D-001, validator v1 bug) and `llama_guard` (D-002, no fixed seed) | **never** |

`phase3-matrix/SOURCES.json` lists, per cell, the source run, `code_commit` (the code that
ran: `3b4ed31` for the 33 original cells, `7a14edc` for the 9 reruns) and the commit the
cell itself recorded (D-004, D-005). `provenance-reruns.json` holds the Ollama version and
model digests for the reruns; the original run predates digest recording (D-005).

All files are copies of `runs/` folders (git-ignored) with their original layout, so
`parry analyze`, `parry matrix-report` and the judge commands read them directly. The secrets
in these files are the lab's fake, HMAC-derived canaries.
