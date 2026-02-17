# Korzent

Korzent is a minimal execution governance standard for verifiable AI and automated systems.

Korzent defines a deterministic, cryptographically verifiable protocol that binds intent, policy, and outcome into signed receipts.

**Specification:** [`PROTOCOL.md`](./PROTOCOL.md)  
**Locked schema:** [`receipt.schema.json`](./receipt.schema.json)

---

## What Korzent Is

- Canonical JSON–based execution receipts  
- Strict schema-hash–anchored verification  
- Ed25519 signature enforcement  
- Authority-before-execution guarantees  
- Deterministic `receipt_id` derivation  
- Fully offline verification  

Korzent defines the invariant execution layer beneath agent runtimes, workflow systems, and orchestration platforms.

---

## What Korzent Is Not

- Not a workflow engine  
- Not an orchestration system  
- Not a task broker  
- Not a SaaS platform  
- Not a coordination layer  

Korzent governs execution authority — it does not coordinate work.

---

## Receipt Kinds (v1.0.0)

Korzent defines three receipt types:

- **EvaluationReceipt** — `ALLOW` or `DENY`  
- **ExecutionReceipt** — `ALLOW` only, links parent `EvaluationReceipt` via `parent_receipt_id`  
- **AttemptReceipt** — `DENY` only, ensures every attempted governed action yields a signed receipt  

---

## Receipt Guarantees

All Korzent receipts are:

- Canonical JSON (RFC8785-compatible)  
- Strictly versioned  
- Schema-hash anchored  
- Cryptographically signed (Ed25519)  
- Deterministically hashed (SHA-256)  
- Verifiable offline  
- Fail-closed on any deviation  

There is no compatibility mode.

---

## Verify a Receipt

From a fresh clone:

```bash
npm ci
npm run verify -- examples/attempt.receipt.json --trust-root examples/demo_pubkey.txt
```

Expected output:

```
VALID OK
```

Any modification to the receipt, schema, signature, or protocol fields results in strict rejection.

---

## Versioning

Protocol version: **1.0.0**

Schema hash:

```
sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f
```

Any modification to `receipt.schema.json` requires:

- A new protocol version  
- A new schema hash  
- Updated verification logic if applicable  

---

## Design Principles

- Minimal surface area  
- Deterministic behavior  
- Cryptographic clarity  
- Explicit authority before execution  
- Strict fail-closed verification  
- No workflow semantics  
- No coordination logic  

---

## License

Apache License 2.0. See [`LICENSE`](./LICENSE) for details.
