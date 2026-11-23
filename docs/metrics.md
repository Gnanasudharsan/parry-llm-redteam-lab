# Metrics

Every number Parry reports is defined here once. Code lives in `parry/metrics.py`.

## Conventions

- **Trials.** One trial = one attack case (template x payload x transform) delivered through
  one channel to one target under one defense configuration, judged once. Lab models run at
  temperature 0 with a fixed seed, so repeating a case returns the same answer; *n* is
  therefore the number of distinct cases, not repeated samples.
- **Scored trials.** Trials that were skipped (channel not available on that target) or
  errored (transport failure) are reported separately and excluded from rates.
- **Seeds.** Every run records its global seed (`seed` in `parry.yaml`, default 1337) and the
  per-trial seeds derived from it. Same config + same seed + same target version = same payloads.
- **Intervals.** Every rate is reported as `point [low, high] (n=…)` with a **95% Wilson score
  interval**. Wilson is used instead of the normal approximation because rates near 0 and 1
  with small *n* are common here, and the Wald interval collapses to zero width there.
  With 0 trials the interval is [0, 1].

## Definitions

| Metric | Definition |
|---|---|
| **Attack success rate (ASR)** | successful trials / trials, sliced by attack family, channel, target and defense |
| **Attempt rate** | trials where the attack steered the target, counting both successes and cases a control stopped (blocked tool call, blocked egress request, or an attacker URL left in the answer but not loaded) / trials |
| **ASR reduction** | ASR(no defense) − ASR(defense), with both intervals shown |
| **False positive rate (FPR)** | benign tasks a defense blocks or alters / benign tasks |
| **Utility retained** | benign task success with defense / benign task success without |
| **Latency overhead** | median and p95 added wall-clock per request, measured on the same machine |
| **Cost overhead** | added tokens per request (and $ at listed prices where an API is used) |
| **Judge accuracy** | agreement of each judge with human labels on a labeled set; precision and recall for "attack succeeded" |
| **Coverage** | OWASP LLM Top 10 (2025) and MITRE ATLAS IDs exercised by each suite, generated from attack metadata |

Hardened targets and defenses are credited only with improvements measured on the same
attack set and seeds as their vulnerable baseline.
