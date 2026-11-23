# ADR 0004: Attacks are data; success is decided by lab evidence first

- Status: accepted
- Date: 2026-11-23

## Context

Attack success rates are only worth reporting if two people running the same suite get the
same number, and if "success" means the same thing for every target. LLM-judged success is
convenient but noisy, can be steered by the very text it grades, and is easy to over-trust.

## Decision

1. **Attacks are YAML templates** (`parry/attacks/catalog/`): family, channel, applicable app
   types, goal, severity, OWASP and ATLAS IDs, payloads, optional obfuscation transforms.
   Templates expand into cases with a nonce derived from the run seed (HMAC), so payloads and
   expected evidence are reproducible.
2. **An attack = generator + channel + judge.** Channels deliver: as the user (direct,
   multi-turn), or by planting content where the app will read it (review, web page, email,
   file, note, tool description) followed by an innocent trigger request.
3. **Goals are benign proxies** with deterministic evidence: a planted canary in output, an
   executed (not blocked) mock tool call, a recorder hit carrying the case nonce, or a marker
   string. The only LLM-judged goal is misinformation, which no string match can decide.
4. **Leak detection decodes**: base64, hex, ROT13, reversed and separator-spaced text, because
   asking for an encoded secret is the obvious way around exact-match redaction.
5. **Success vs attempt.** A trial is *attempted* when the model was steered but a control
   stopped the effect (a blocked tool call, a blocked egress request, an attacker URL in the answer that was never loaded). Reporting
   both separates "the model resisted" from "the guardrail caught it".
6. **Judge accuracy is measured, not assumed.** `parry judge sample` draws a stratified set of
   outcomes and adds a generic LLM-judge verdict to each; a human labels them blind
   (`parry judge label`); `parry judge eval` reports accuracy, precision and recall per judge.
7. **Skipped and errored trials are reported separately** and never counted as failures of
   the attack, so infrastructure problems cannot lower an ASR.

## Consequences

- With temperature 0 and a fixed model seed, re-running a case gives the same answer, so
  *n* counts distinct cases, and intervals are wide for small families. That is shown, not hidden.
- Partial leaks (a prefix of a canary, a description of its format) are not counted.
- The LLM judge uses the same local model family as the targets; its accuracy is reported
  against human labels before any claim relies on it.
