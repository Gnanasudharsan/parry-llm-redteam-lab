# ADR 0001: Target authorization is enforced in code, per target, per run

- Status: accepted
- Date: 2026-11-23

## Context

Parry sends prompt-injection and data-exfiltration attempts. Pointed at the wrong system,
that is unauthorized testing. A config file alone is weak protection: configs get copied,
shared and edited, and a single "authorized: true" line is easy to inherit by accident.

## Decision

1. A target runs only if it is in `parry.yaml` **and** named on that invocation with
   `--i-own-this-target <name>`. There is no wildcard.
2. Each target carries a free-text `owner_statement` (at least 10 characters) that is kept in
   reports, so every result records why testing it was allowed.
3. Endpoints are classified by literal host: in-process, loopback, private (RFC 1918/ULA/
   link-local, `.test`, `.internal`, `.local`, `.lan`, `.home.arpa`, single-label Compose
   service names), or public. Public endpoints need both
   `public_endpoint_acknowledged: true` and `--allow-public-endpoints`.
4. LiteLLM targets without a `url` go to a hosted provider and count as public.
5. The gate lives in one function (`parry.scope.authorize`) that every scan path calls.

## Consequences

- Scanning N targets needs N flags; that friction is deliberate.
- No DNS resolution: a private-looking name resolving to a public IP passes as private. We
  accept this to keep the gate deterministic and offline; it is documented in SECURITY.md.
  Egress enforcement for the lab is handled separately by Docker network isolation (Phase 1).
- CI usage (Phase 5) passes the flags explicitly in the workflow file, so authorization is
  visible in code review.
