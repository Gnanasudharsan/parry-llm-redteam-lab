# ADR 0005: Defenses are measured one at a time, on the same app, with utility alongside

- Status: accepted
- Date: 2026-11-23

## Context

"Hardened" in Phase 2 meant eight controls switched on at once, which shows that the set
helps but not which control does the work, what each costs in usefulness, or what a guard
model adds. A defense that blocks attacks by also refusing normal requests is not a win, so
security and utility have to be measured on the same app state.

## Decision

1. **Two kinds of defense, one interface.** Target-side controls (spotlighting, instruction
   hierarchy, ACLs, redaction, markdown sanitization, egress and tool policies) stay as lab
   flags. Parry defense layers (`parry/defenses`) inspect text at three hooks (`input`,
   `untrusted`, `output`) and the app decides the action: refuse the request, drop the
   document, replace the tool output.
2. **Runtime reconfiguration.** `PUT /_lab/config` sets flags and layers on a running
   *vulnerable* container, so every configuration starts from identical code, data and model.
3. **Guards run on the host** (`parry guard serve` for encoder classifiers, Ollama for
   Llama Guard) and are reached through the lab gateway; lab containers stay small and keep
   no internet route. A failing guard fails open and the failure is recorded.
4. **Every matrix cell runs the attack suite and the benign set** back to back. Reported per
   cell: ASR and critical ASR (Wilson CIs), benign pass rate, false-positive rate (benign
   tasks where any layer fired or any control blocked), utility retained vs `none`, median
   and p95 request latency on benign tasks, guard time and guard tokens per request.
5. **Pareto view.** A configuration is Pareto-optimal if no other configuration has both
   lower ASR and higher utility. Cost (latency, guard tokens) is reported next to it rather
   than folded into a single score, because the right trade-off depends on the app.
6. **Baseline scanner.** NVIDIA garak runs through its REST generator on the same chat
   endpoints, behind Parry's `--i-own-this-target` gate, with probes limited to benign
   injection, encoding and markdown-exfiltration payloads.

## Consequences

- One vulnerable container per app is reused for every configuration; cells run
  sequentially so they do not compete for the model, and latency numbers are comparable.
- Main-model token overhead of prompt-side controls (longer system prompts) is not measured;
  only guard tokens are.
- The output validator knows the lab's secret formats; its numbers say what format-aware
  output rules can do, not what a generic secret detector would.
