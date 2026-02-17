# Korzent — Repository Governance

VERSION: v1.0  
SCOPE: Korzent Execution Governance Standard only.

---

## Purpose

This repository defines the Korzent Execution Governance Standard.

It specifies deterministic, cryptographically verifiable receipt behavior.  
It does **not** define runtime systems, orchestration engines, SaaS services, operator authentication, or policy marketplaces.

---

## Invariants

### 1. Protocol Stability and Versioning

- Any change to `receipt.schema.json`, canonicalization rules, hashing rules, signature encoding, receipt kinds, or verification behavior constitutes a protocol change.
- Protocol changes require a semantic version bump.
- Schema changes require updating the locked `schema_hash` constant.
- Verification outcomes must remain deterministic for a given protocol version.

### 2. Strict Verification

- Korzent v1 enforces strict validation.
- Compatibility modes or lenient parsing paths are not permitted.
- `additionalProperties: false` remains enforced across receipt variants.

### 3. Deterministic Reproducibility

- Protocol-affecting changes must include deterministic test vectors.
- Tests must prove verification behavior for all receipt kinds.
- Independent implementations must be able to reproduce identical verification outcomes.

### 4. Demo Material

- Any signing keys included in the repository are for demonstration purposes only.
- No production signing keys may be committed.

---

## Scope Boundaries

The following concerns are explicitly out of scope for this repository:

- Operator authentication logic  
- Runtime authorization enforcement  
- SaaS configuration  
- Key registry services  
- Orchestration engines  
- Replay engines  
- Marketplace or economic features  

These belong in higher-layer implementations.

---

## Change Discipline

Pull requests that modify protocol-defining files must:

- Clearly state whether the change is protocol-breaking or non-breaking.
- Update version identifiers where required.
- Preserve deterministic verification behavior within the same protocol version.
