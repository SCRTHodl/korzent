# Korzent — Repository Governance

VERSION: v1.0
SCOPE: Korzent Execution Governance Standard only.

## Purpose

This repository defines a deterministic execution governance standard.
It is NOT a runtime, SaaS, gateway, orchestration engine, or policy marketplace.

## Invariants (Korzent-Specific)

1) No protocol drift without SemVer change
- Any change to receipt.schema.json, hashing rules, canonicalization rules, signature encoding, receipt kinds, or verification behavior requires a version bump.
- Any schema change requires updating the locked schema hash where applicable.

2) Strict verification only
- No compatibility mode in v1.
- No lenient parsing paths.
- additionalProperties: false remains enforced.

3) Deterministic reproducibility
- Protocol-affecting changes MUST include deterministic test vectors and tests proving verification outcomes.

4) Demo keys are demo-only
- No production signing keys are ever committed.
- Any keys in examples are explicitly demo-only.

## Scope Restrictions

Out of scope:
- Operator auth logic
- SaaS configuration
- Key registry services
- Orchestration logic
- Replay engines
- Marketplace features

Those belong in higher-layer repos.

## Stop Conditions

STOP if:
- Any change alters verifier accept/reject behavior without SemVer bump.
- Any change modifies receipt.schema.json without version bump.
- Canonicalization behavior changes without explicit version bump and updated proofs.
