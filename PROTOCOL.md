# KORZENT Execution Governance Standard v1

**Locked v1 schema hash:** `sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f`

## Normative Rules

1. **Canonicalization (RFC8785)**
   - All signed and hashed JSON values MUST be canonicalized with RFC8785 (JSON Canonicalization Scheme).
   - Canonicalization output MUST be byte-stable across platforms and runtimes.
   - Implementations MUST treat canonicalization as a deterministic, pure function with no runtime-dependent formatting behavior.

2. **Hashing algorithm and encoding**
   - Hash algorithm: SHA-256.
   - Hash reference encoding: `sha256:<lower-hex>` where `<lower-hex>` is exactly 64 lowercase hexadecimal characters.

3. **`schema_hash` derivation**
   - `schema_hash = "sha256:" + SHA256(RFC8785(canonical JSON of receipt.schema.json)).hexLower`
   - `schema_hash` MUST equal `KORZENT_V1_SCHEMA_HASH` exactly.

4. **Protocol identity and fork defense**
   - `protocol` field MUST be exactly `"korzent"`.
   - `protocol_version` field MUST be exactly `"1.0.0"`.
   - `protocol_id = "korzent:1.0.0:" + KORZENT_V1_SCHEMA_HASH`.

5. **`receipt_id` derivation**
   - Let `unsigned_receipt_json_for_id` be the receipt object with both `signature` and `receipt_id` omitted.
   - `receipt_id = "sha256:" + SHA256(RFC8785(unsigned_receipt_json_for_id)).hexLower`

6. **Ed25519 signing rules**
   - Signature encoding is locked to base64url (no padding) and MUST be exactly 86 characters.
   - Let `unsigned_receipt_json_for_sig` be the receipt object with `signature` omitted (and with derived `receipt_id` present).
   - `signature = Ed25519Sign(privateKey, SHA256(RFC8785(unsigned_receipt_json_for_sig)))`
   - The exact bytes signed are the 32-byte SHA-256 digest of canonicalized unsigned receipt JSON.

7. **Receipt kinds**
   - **EvaluationReceipt**: policy evaluation output (`decision` is `ALLOW` or `DENY`).
   - **ExecutionReceipt**: execution output for `ALLOW` only; MUST include `parent_receipt_id` linking to its decision receipt.
   - **AttemptReceipt**: boundary pre-evaluate failure receipt (`decision` is `DENY` only) used to satisfy always-receipt behavior.

8. **`intent_hash` derivation**
   - `intent_hash = "sha256:" + SHA256(RFC8785(intent_json)).hexLower`
   - `intent_hash` MUST NOT be `ZERO_HASH`.

9. **`ZERO_HASH` placeholder policy (tight)**
   - `ZERO_HASH = "sha256:" + 64 * "0"`.
   - `ZERO_HASH` is allowed **only** for AttemptReceipt `policy_pack_hash` and `epoch_hash` when those values are unavailable.
   - `ZERO_HASH` is forbidden for:
     - `intent_hash` in all receipt kinds
     - `policy_pack_hash` and `epoch_hash` in EvaluationReceipt and ExecutionReceipt.

10. **Attempt intent hash rule (pre-evaluate failures)**
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

11. **Strict verifier behavior (no compatibility mode)**
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
