import { createHash } from 'node:crypto';
import { describe, expect, it } from '../../services/action-gateway/node_modules/vitest/dist/index.js';
import * as ed from '../../services/action-gateway/node_modules/@noble/ed25519/index.js';
import Ajv2020 from '../../services/action-gateway/node_modules/ajv/dist/2020.js';
import { canonicalizeJsonToBytes } from '../src/canonical.js';
import { sha256Ref } from '../src/hash.js';
import { KORZENT_V1_RECEIPT_SCHEMA, KORZENT_V1_SCHEMA_HASH } from '../src/schema.js';
import { deriveReceiptId, signReceipt } from '../src/sign.js';
import { verifyReceipt } from '../src/verify.js';
import { ZERO_HASH } from '../src/types.js';
import type {
  TrustRoots,
  UnsignedAttemptReceiptV1,
  UnsignedEvaluateReceiptV1,
  UnsignedExecutionReceiptV1,
} from '../src/types.js';

ed.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => {
  const hash = createHash('sha512');
  for (const message of messages) {
    hash.update(message);
  }
  return new Uint8Array(hash.digest());
};

const PRIVATE_KEY = new Uint8Array([
  1, 35, 69, 103, 137, 171, 205, 239,
  16, 50, 84, 118, 152, 186, 220, 254,
  17, 34, 51, 68, 85, 102, 119, 136,
  153, 170, 187, 204, 221, 238, 240, 15,
]);
const PUBLIC_KEY = ed.getPublicKey(PRIVATE_KEY);
const validateSchema = new Ajv2020({ allErrors: true, strict: false }).compile(KORZENT_V1_RECEIPT_SCHEMA);

function hashIntent(intent: Record<string, unknown>): `sha256:${string}` {
  return sha256Ref(canonicalizeJsonToBytes(intent));
}

function makeUnsignedEvaluateReceipt(): UnsignedEvaluateReceiptV1 {
  return {
    protocol: 'korzent',
    protocol_version: '1.0.0',
    schema_hash: KORZENT_V1_SCHEMA_HASH,
    trust_root_id: 'root-main',
    intent_hash: hashIntent({ action: 'payment', amount: 20, currency: 'USD' }),
    policy_pack_hash: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    decision: 'ALLOW',
    inputs_snapshot_hash: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    epoch_hash: 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    timestamp_utc: '2026-02-16T23:00:00.000Z',
    signing_key_id: 'k1',
  };
}

function makeUnsignedAttemptReceipt(): UnsignedAttemptReceiptV1 {
  const inputs_snapshot_hash = sha256Ref(canonicalizeJsonToBytes({
    route: '/v1/actions/governed',
    request: {
      action_type: 'payment.create',
      target_system: 'stripe_sim',
      payload: { amount: 20, currency: 'USD' },
    },
  }));
  const attemptIntent = {
    kind: 'ATTEMPT',
    route: '/v1/actions/governed',
    deny_code: 'MISSING_ENV',
    inputs_snapshot_hash,
    driver: 'stripe_sim.charge',
  };

  return {
    protocol: 'korzent',
    protocol_version: '1.0.0',
    schema_hash: KORZENT_V1_SCHEMA_HASH,
    trust_root_id: 'root-main',
    intent_hash: sha256Ref(canonicalizeJsonToBytes(attemptIntent)),
    policy_pack_hash: ZERO_HASH,
    decision: 'DENY',
    inputs_snapshot_hash,
    epoch_hash: ZERO_HASH,
    timestamp_utc: '2026-02-16T23:00:00.000Z',
    signing_key_id: 'k1',
    deny_code: 'MISSING_ENV',
    deny_message: 'required governed configuration unavailable',
  };
}

function makeUnsignedExecutionReceipt(): UnsignedExecutionReceiptV1 {
  return {
    protocol: 'korzent',
    protocol_version: '1.0.0',
    schema_hash: KORZENT_V1_SCHEMA_HASH,
    trust_root_id: 'root-main',
    intent_hash: hashIntent({ action: 'execute', driver: 'stripe_sim.charge', amount: 20, currency: 'USD' }),
    policy_pack_hash: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    decision: 'ALLOW',
    inputs_snapshot_hash: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    epoch_hash: 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    timestamp_utc: '2026-02-16T23:00:00.000Z',
    signing_key_id: 'k1',
    parent_receipt_id: 'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    action_driver: 'stripe_sim.charge',
    payload_hash: 'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    result_hash: 'sha256:6666666666666666666666666666666666666666666666666666666666666666',
  };
}

function makeSignedExecutionReceipt() {
  const unsigned = makeUnsignedExecutionReceipt();
  const withReceiptId = {
    ...unsigned,
    receipt_id: deriveReceiptId(unsigned),
  };
  return {
    ...withReceiptId,
    signature: signReceipt(withReceiptId, PRIVATE_KEY),
  };
}

function makeSignedAttemptReceipt() {
  const unsigned = makeUnsignedAttemptReceipt();
  const withReceiptId = {
    ...unsigned,
    receipt_id: deriveReceiptId(unsigned),
  };
  return {
    ...withReceiptId,
    signature: signReceipt(withReceiptId, PRIVATE_KEY),
  };
}

function makeSignedEvaluateReceipt() {
  const unsigned = makeUnsignedEvaluateReceipt();
  const withReceiptId = {
    ...unsigned,
    receipt_id: deriveReceiptId(unsigned),
  };
  return {
    ...withReceiptId,
    signature: signReceipt(withReceiptId, PRIVATE_KEY),
  };
}

function trustRoots(): TrustRoots {
  return {
    'root-main': {
      k1: Buffer.from(PUBLIC_KEY).toString('base64url'),
    },
  };
}

describe('verifyReceipt strict rules', () => {
  it('accepts a well-formed signed receipt under an allowed trust root', () => {
    const receipt = makeSignedEvaluateReceipt();
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: true, code: 'OK' });
  });

  it('accepts AttemptReceipt with ZERO_HASH placeholders for policy and epoch', () => {
    const receipt = makeSignedAttemptReceipt();
    expect(validateSchema(receipt)).toBe(true);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: true, code: 'OK' });
  });

  it('rejects missing protocol', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.protocol;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_MISSING_PROTOCOL' });
  });

  it('rejects unknown version', () => {
    const receipt = { ...makeSignedEvaluateReceipt(), protocol_version: '2.0.0' };
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_UNKNOWN_PROTOCOL_VERSION' });
  });

  it('rejects missing schema_hash', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.schema_hash;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SCHEMA_HASH_MISSING' });
  });

  it('rejects schema hash mismatch', () => {
    const receipt = {
      ...makeSignedEvaluateReceipt(),
      schema_hash: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    };
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SCHEMA_HASH_MISMATCH' });
  });

  it('rejects missing trust_root_id', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.trust_root_id;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_TRUST_ROOT_ID_MISSING' });
  });

  it('rejects missing signing_key_id', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.signing_key_id;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SIGNING_KEY_ID_MISSING' });
  });

  it('rejects missing required fields', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.intent_hash;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_REQUIRED_FIELD_MISSING:intent_hash' });
  });

  it('rejects invalid signature', () => {
    const receipt = {
      ...makeSignedEvaluateReceipt(),
      signature: 'aW52YWxpZC1zaWduYXR1cmU',
    };
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SIGNATURE_INVALID' });
  });

  it('rejects signature length != 86 by schema and verifyReceipt', () => {
    const receipt = {
      ...makeSignedEvaluateReceipt(),
      signature: makeSignedEvaluateReceipt().signature.slice(0, 85),
    };
    expect(validateSchema(receipt)).toBe(false);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SIGNATURE_INVALID' });
  });

  it('rejects unsigned receipt', () => {
    const receipt = makeSignedEvaluateReceipt() as Record<string, unknown>;
    delete receipt.signature;
    const result = verifyReceipt(receipt as never, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SIGNATURE_MISSING' });
  });

  it('rejects receipt_id mismatch', () => {
    const receipt = {
      ...makeSignedEvaluateReceipt(),
      receipt_id: 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    };
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_RECEIPT_ID_MISMATCH' });
  });

  it('rejects executionReceipt with decision DENY', () => {
    const receipt = { ...makeSignedExecutionReceipt(), decision: 'DENY' };
    expect(validateSchema(receipt)).toBe(false);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_DECISION_INVALID' });
  });

  it('rejects AttemptReceipt if decision is not DENY', () => {
    const attempt = makeSignedAttemptReceipt();
    const mutated = {
      ...attempt,
      decision: 'ALLOW',
    };
    const withReceiptId = {
      ...mutated,
      receipt_id: deriveReceiptId(mutated),
    };
    const receipt = {
      ...withReceiptId,
      signature: signReceipt(withReceiptId, PRIVATE_KEY),
    };

    expect(validateSchema(receipt)).toBe(false);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_DECISION_INVALID' });
  });

  it('rejects EvaluationReceipt with ZERO_HASH policy_pack_hash', () => {
    const mutated = {
      ...makeUnsignedEvaluateReceipt(),
      policy_pack_hash: ZERO_HASH,
    };
    const withReceiptId = {
      ...mutated,
      receipt_id: deriveReceiptId(mutated),
    };
    const receipt = {
      ...withReceiptId,
      signature: signReceipt(withReceiptId, PRIVATE_KEY),
    };

    expect(validateSchema(receipt)).toBe(false);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_ZERO_HASH_FORBIDDEN:policy_pack_hash' });
  });

  it('rejects any receipt with ZERO_HASH intent_hash', () => {
    const mutated = {
      ...makeUnsignedEvaluateReceipt(),
      intent_hash: ZERO_HASH,
    };
    const withReceiptId = {
      ...mutated,
      receipt_id: deriveReceiptId(mutated),
    };
    const receipt = {
      ...withReceiptId,
      signature: signReceipt(withReceiptId, PRIVATE_KEY),
    };

    expect(validateSchema(receipt)).toBe(false);
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_ZERO_HASH_FORBIDDEN:intent_hash' });
  });

  it('rejects trust roots outside caller-supplied map', () => {
    const receipt = makeSignedEvaluateReceipt();
    const result = verifyReceipt(receipt, {});
    expect(result).toEqual({ ok: false, code: 'ERR_TRUST_ROOT_UNKNOWN' });
  });

  it('rejects unknown signing key for known trust root', () => {
    const mutated = { ...makeSignedEvaluateReceipt(), signing_key_id: 'unknown-kid' };
    const receiptWithDerivedId = {
      ...mutated,
      receipt_id: deriveReceiptId(mutated),
    };
    const receipt = {
      ...receiptWithDerivedId,
      signature: signReceipt(receiptWithDerivedId, PRIVATE_KEY),
    };
    const result = verifyReceipt(receipt, trustRoots());
    expect(result).toEqual({ ok: false, code: 'ERR_SIGNING_KEY_UNKNOWN' });
  });
});
