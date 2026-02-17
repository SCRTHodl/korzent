Korzent

Korzent is a minimal execution governance standard for verifiable AI and automated systems.

Korzent defines a deterministic, cryptographically verifiable protocol that binds intent, policy, and outcome into signed receipts.

What Korzent Is

Canonical JSON–based execution receipts

Strict schema-hash–anchored verification

Ed25519 signature enforcement

Authority-before-execution guarantees

Deterministic receipt_id derivation

Fully offline verification

What Korzent Is Not

Not a workflow engine

Not an orchestration system

Not a task broker

Not a SaaS platform

Not a coordination layer

Korzent is the invariant execution layer beneath those systems.

Receipt Kinds (v1.0.0)

EvaluationReceipt (ALLOW or DENY)

ExecutionReceipt (ALLOW only, links parent EvaluationReceipt)

AttemptReceipt (DENY only, ensures every attempt yields a signed receipt)

All receipts are:

Canonical JSON

Strictly versioned

Schema-hash anchored

Cryptographically signed

Verifiable offline

Verify a Receipt

npm run verify -- examples/attempt.receipt.json --trust-root examples/demo_pubkey.txt

Expected output:

VALID OK

Any deviation results in strict rejection.

Versioning

Protocol version: 1.0.0

Schema hash: sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f

Any modification to receipt.schema.json requires a version bump and new schema hash.

License

Apache License 2.0. See LICENSE for details.
