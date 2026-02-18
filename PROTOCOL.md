# KORZENT Execution Governance Standard v1.0.0

**Locked v1 schema hash:** `sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f`

## Abstract

Korzent defines a deterministic, cryptographically verifiable execution governance standard. It binds intent, policy, and outcome into signed receipts that can be verified offline without coordination services. The protocol is intentionally minimal: canonical JSON, schema-hash anchoring, Ed25519 signatures, and strict fail-closed verification. Korzent does not define runtimes, orchestration, or coordination—only the invariant receipt layer that proves authority-before-execution and auditability after the fact.

## Design Goals

- **Deterministic**: identical verification outcomes across platforms and implementations
- **Minimal surface area**: only what is required to prove authority and auditability
- **Cryptographic clarity**: canonical JSON, Ed25519, SHA-256 with explicit encoding rules
- **Fail-closed**: any deviation results in rejection; no compatibility modes
- **Offline verifiable**: receipts can be verified without network calls or coordination services

## Scope

Korzent specifies:
- Receipt structure and canonicalization rules
- Schema-hash anchoring and protocol identity
- Ed25519 signing and receipt_id derivation
- Three receipt kinds: Evaluation, Execution, Attempt
- Strict verification invariants

Out of scope:
- Runtime authorization enforcement
- Operator authentication systems
- Policy distribution or key registry services
- Orchestration engines or workflow semantics
- SaaS configuration or marketplace features

These belong in higher-layer implementations.

## Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## 4. Normative Requirements

### 4.1 Canonicalization (RFC8785)
- All signed and hashed JSON values MUST be canonicalized with RFC8785 (JSON Canonicalization Scheme).
- Canonicalization output MUST be byte-stable across platforms and runtimes.
- Implementations MUST treat canonicalization as a deterministic, pure function with no runtime-dependent formatting behavior.

### 4.2 Hashing algorithm and encoding
- Hash algorithm: SHA-256.
- Hash reference encoding: `sha256:<lower-hex>` where `<lower-hex>` is exactly 64 lowercase hexadecimal characters.

### 4.3 `schema_hash` derivation
- `schema_hash = "sha256:" + SHA256(RFC8785(canonical JSON of receipt.schema.json)).hexLower`
- `schema_hash` MUST equal `KORZENT_V1_SCHEMA_HASH` exactly.

### 4.4 Protocol identity and fork defense
- `protocol` field MUST be `"korzent"`.
- `protocol_version` field MUST be `"1.0.0"`.
- `protocol_id = "korzent:1.0.0:" + KORZENT_V1_SCHEMA_HASH`.

### 4.5 `receipt_id` derivation
- Let `unsigned_receipt_json_for_id` be the receipt object with both `signature` and `receipt_id` omitted.
- `receipt_id = "sha256:" + SHA256(RFC8785(unsigned_receipt_json_for_id)).hexLower`

### 4.6 Ed25519 signing rules
- Signature encoding is locked to base64url (no padding) and MUST be exactly 86 characters.
- Let `unsigned_receipt_json_for_sig` be the receipt object with `signature` omitted (and with derived `receipt_id` present).
- `signature = Ed25519Sign(privateKey, SHA256(RFC8785(unsigned_receipt_json_for_sig)))`
- The exact bytes signed are the 32-byte SHA-256 digest of canonicalized unsigned receipt JSON.

### 4.7 Receipt kinds
- **EvaluationReceipt**: policy evaluation output (`decision` is `ALLOW` or `DENY`).
- **ExecutionReceipt**: execution output for `ALLOW` only; MUST include `parent_receipt_id` linking to its decision receipt.
- **AttemptReceipt**: boundary pre-evaluate failure receipt (`decision` is `DENY` only) to satisfy always-receipt behavior.

### 4.8 `intent_hash` derivation
- `intent_hash = "sha256:" + SHA256(RFC8785(intent_json)).hexLower`
- `intent_hash` MUST NOT be ` `ZERO_HASH`.

### 4.9 `ZERO_HASH` placeholder policy (tight)
- `ZERO_HASH = "sha256:" + 64 * "0"`.
- `ZERO_HASH` is allowed **only** for AttemptReceipt `policy_pack_hash` and `epoch_hash` when those values are unavailable.
- `ZERO_HASH` is forbidden for:
  - `intent_hash` in all receipt kinds
  - `policy_pack_hash` and `epoch_hash` in EvaluationReceipt and ExecutionReceipt.

### 4.10 Attempt intent hash rule (pre-evaluate failures)
- AttemptReceipt intent hashing uses a deterministic portable payload:

```json
{
  "kind": "ATTEMPT",
  "route": "/v1/actions/governed",
  "deny_code": "<deny_code>",
  "inputs_snapshot_hash": "<hashRef>",
  "driver": "<driver_name_or_empty_string>"
}
```

- AttemptReceipt `intent_hash` MUST be the RFC8785 SHA-256 hash-ref of this object.

### 4.11 Strict verifier behavior (no compatibility mode)
- Reject if `protocol != "korzent"`.
- Reject if `protocol_version != "1.0.0"`.
- Reject if `schema_hash` is missing.
- Reject if `schema_hash != KORZENT_V1_SCHEMA_HASH`.
- Reject if `trust_root_id` is missing.
- Reject if `signing_key_id` is missing.
- Reject if `signature` is missing or invalid.
- Reject if signature length is not exactly 86.
- Reject if any required schema field is missing.
- Reject if execution receipt has `decision != "ALLOW"`.
- Reject if attempt receipt has `decision != "DENY"`.
- Reject if attempt receipt `deny_code` is missing/invalid.
- Reject if attempt receipt `deny_message` is present but empty or >256 chars.
- Reject if `receipt_id` does not equal derived `receipt_id`.
- Trust roots are caller-supplied; verifier MUST accept only receipts whose (`trust_root_id`, `signing_key_id`) maps to a known public key.

## 5. Conformance

### 5.1 Receipt Producer
A Receipt Producer MUST:
- Emit receipts that conform to the schema and all normative requirements.
- Compute canonicalization, hashes, and signatures exactly as specified.
- Include a valid `receipt_id` and `signature` for every receipt.

### 5.2 Verifier
A Verifier MUST:
- Implement strict verification as defined in 4.11.
- Reject any deviation without fallback or compatibility mode.
- Accept only receipts with known (`trust_root_id`, `signing_key_id`) mappings.

### 5.3 Executor
An Executor MUST:
- Accept only EvaluationReceipts with `decision: "ALLOW"` for execution.
- Link ExecutionReceipts to the parent EvaluationReceipt via `parent_receipt_id`.
- Emit an AttemptReceipt for any governed action that cannot be evaluated or executed.

## 6. Security Considerations

- Implementations MUST validate Ed25519 signatures using constant-time operations.
- Private signing keys MUST be protected and never exposed in receipts or logs.
- Demo keys in examples are for demonstration only and MUST NOT be used in production.
- Receipts contain cryptographic proofs; tampering with any field invalidates the signature.
- The `schema_hash` binds verification to a specific schema version; changing the schema requires a protocol version update.

## Appendix A — Locked v1 Constants

- `KORZENT_PROTOCOL`: `"korzent"`
- `KORZENT_PROTOCOL_VERSION`: `"1.0.0"`
- `KORZENT_V1_SCHEMA_HASH`: `sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f`
- `ZERO_HASH`: `sha256:0000000000000000000000000000000000000000000000000000000000000000`

## Appendix B — Test Vectors

Deterministic test vectors are provided in `test-vectors/` with the following files:

| Vector | Kind | Decision | File |
|--------|------|----------|------|
| eval_deny | EVALUATION | DENY | `test-vectors/eval_deny.receipt.json` |
| eval_allow | EVALUATION | ALLOW | `test-vectors/eval_allow.receipt.json` |
| exec_allow | EXECUTION | ALLOW | `test-vectors/exec_allow.receipt.json` |
| attempt_deny | ATTEMPT | DENY | `test-vectors/attempt_deny.receipt.json` |

Running the test suite validates these vectors:

```bash
npm test
```

CLI verification example using a test vector:

```bash
npm run verify -- test-vectors/attempt_deny.receipt.json --trust-root examples/demo_pubkey.txt
```

Expected output: `VALID OK`
