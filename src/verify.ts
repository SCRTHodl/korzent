import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { canonicalizeJsonToBytes } from './canonical.js';
import { deriveReceiptId } from './sign.js';
import { KORZENT_V1_SCHEMA_HASH } from './schema.js';
import {
  ATTEMPT_DENY_CODES,
  ZERO_HASH,
  type HashRef,
  type TrustRootKey,
  type TrustRoots,
  type VerifyResult,
} from './types.js';

const HASH_REF_RE = /^sha256:[0-9a-f]{64}$/;
const TIMESTAMP_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

const require = createRequire(import.meta.url);

const ed = require('../../services/action-gateway/node_modules/@noble/ed25519/index.js') as {
  etc: { sha512Sync: (...messages: Uint8Array[]) => Uint8Array };
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;
};

ed.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => {
  const hash = createHash('sha512');
  for (const message of messages) {
    hash.update(message);
  }
  return new Uint8Array(hash.digest());
};

function fail(code: string): VerifyResult {
  return { ok: false, code };
}

function hasNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.length > 0;
}

function isHashRef(value: unknown): value is HashRef {
  return typeof value === 'string' && HASH_REF_RE.test(value);
}

function requiredFieldMissing(receipt: Record<string, unknown>, key: string): boolean {
  if (!(key in receipt)) return true;
  const value = receipt[key];
  if (typeof value === 'string') return value.length === 0;
  return value === null || typeof value === 'undefined';
}

function decodeBase64Url(value: string): Uint8Array {
  try {
    return Buffer.from(value, 'base64url');
  } catch {
    return new Uint8Array();
  }
}

function normalizePublicKey(value: TrustRootKey): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  return decodeBase64Url(value);
}

function resolvePublicKey(receipt: Record<string, unknown>, trustRoots: TrustRoots): Uint8Array | null {
  const trustRootId = receipt.trust_root_id as string;
  const signingKeyId = receipt.signing_key_id as string;
  const trustRoot = trustRoots[trustRootId];
  if (!trustRoot) {
    return null;
  }
  const keyValue = trustRoot[signingKeyId];
  if (!keyValue) {
    return null;
  }
  const keyBytes = normalizePublicKey(keyValue);
  return keyBytes.length === 32 ? keyBytes : null;
}

const ATTEMPT_DENY_CODE_SET = new Set<string>(ATTEMPT_DENY_CODES);

function isAttemptReceipt(candidate: Record<string, unknown>): boolean {
  return 'deny_code' in candidate || 'deny_message' in candidate;
}

function isAttemptDenyCode(value: unknown): boolean {
  return typeof value === 'string' && ATTEMPT_DENY_CODE_SET.has(value);
}

export function verifyReceipt(receipt: unknown, trustRoots: TrustRoots): VerifyResult {
  const candidate = receipt as Record<string, unknown>;
  if (!candidate || typeof candidate !== 'object') {
    return fail('ERR_RECEIPT_MALFORMED');
  }

  if (requiredFieldMissing(candidate, 'protocol')) {
    return fail('ERR_MISSING_PROTOCOL');
  }
  if (candidate.protocol !== 'korzent') {
    return fail('ERR_PROTOCOL_MISMATCH');
  }

  if (requiredFieldMissing(candidate, 'protocol_version')) {
    return fail('ERR_MISSING_PROTOCOL_VERSION');
  }
  if (candidate.protocol_version !== '1.0.0') {
    return fail('ERR_UNKNOWN_PROTOCOL_VERSION');
  }

  if (requiredFieldMissing(candidate, 'schema_hash')) {
    return fail('ERR_SCHEMA_HASH_MISSING');
  }
  if (candidate.schema_hash !== KORZENT_V1_SCHEMA_HASH) {
    return fail('ERR_SCHEMA_HASH_MISMATCH');
  }

  if (requiredFieldMissing(candidate, 'trust_root_id')) {
    return fail('ERR_TRUST_ROOT_ID_MISSING');
  }
  if (!hasNonEmptyString(candidate.trust_root_id)) {
    return fail('ERR_TRUST_ROOT_ID_INVALID');
  }

  if (requiredFieldMissing(candidate, 'signing_key_id')) {
    return fail('ERR_SIGNING_KEY_ID_MISSING');
  }
  if (!hasNonEmptyString(candidate.signing_key_id)) {
    return fail('ERR_SIGNING_KEY_ID_INVALID');
  }

  if (requiredFieldMissing(candidate, 'signature')) {
    return fail('ERR_SIGNATURE_MISSING');
  }
  if (!hasNonEmptyString(candidate.signature)) {
    return fail('ERR_SIGNATURE_INVALID');
  }

  const commonRequired = [
    'receipt_id',
    'intent_hash',
    'policy_pack_hash',
    'decision',
    'inputs_snapshot_hash',
    'epoch_hash',
    'timestamp_utc',
  ];

  for (const key of commonRequired) {
    if (requiredFieldMissing(candidate, key)) {
      return fail(`ERR_REQUIRED_FIELD_MISSING:${key}`);
    }
  }

  if (candidate.decision !== 'ALLOW' && candidate.decision !== 'DENY') {
    return fail('ERR_DECISION_INVALID');
  }

  if (!TIMESTAMP_UTC_RE.test(String(candidate.timestamp_utc))) {
    return fail('ERR_TIMESTAMP_UTC_INVALID');
  }

  const hashFields = ['schema_hash', 'receipt_id', 'intent_hash', 'policy_pack_hash', 'inputs_snapshot_hash', 'epoch_hash'];
  for (const key of hashFields) {
    if (!isHashRef(candidate[key])) {
      return fail(`ERR_HASH_REF_INVALID:${key}`);
    }
  }

  if (candidate.intent_hash === ZERO_HASH) {
    return fail('ERR_ZERO_HASH_FORBIDDEN:intent_hash');
  }

  if (isAttemptReceipt(candidate)) {
    if (candidate.decision !== 'DENY') {
      return fail('ERR_DECISION_INVALID');
    }
    if (requiredFieldMissing(candidate, 'deny_code')) {
      return fail('ERR_REQUIRED_FIELD_MISSING:deny_code');
    }
    if (!isAttemptDenyCode(candidate.deny_code)) {
      return fail('ERR_DENY_CODE_INVALID');
    }
    if ('deny_message' in candidate) {
      if (typeof candidate.deny_message !== 'string' || candidate.deny_message.length === 0 || candidate.deny_message.length > 256) {
        return fail('ERR_DENY_MESSAGE_INVALID');
      }
    }
  } else {
    if (candidate.policy_pack_hash === ZERO_HASH) {
      return fail('ERR_ZERO_HASH_FORBIDDEN:policy_pack_hash');
    }
    if (candidate.epoch_hash === ZERO_HASH) {
      return fail('ERR_ZERO_HASH_FORBIDDEN:epoch_hash');
    }
  }

  const executionFields = ['parent_receipt_id', 'action_driver', 'payload_hash', 'result_hash'];
  const executionPresent = executionFields.filter((key) => key in candidate).length;
  if (executionPresent !== 0 && executionPresent !== executionFields.length) {
    for (const key of executionFields) {
      if (requiredFieldMissing(candidate, key)) {
        return fail(`ERR_REQUIRED_FIELD_MISSING:${key}`);
      }
    }
  }

  if (executionPresent === executionFields.length) {
    if (candidate.decision !== 'ALLOW') {
      return fail('ERR_DECISION_INVALID');
    }
    if (!isHashRef(candidate.parent_receipt_id)) {
      return fail('ERR_HASH_REF_INVALID:parent_receipt_id');
    }
    if (!hasNonEmptyString(candidate.action_driver)) {
      return fail('ERR_REQUIRED_FIELD_MISSING:action_driver');
    }
    if (!isHashRef(candidate.payload_hash)) {
      return fail('ERR_HASH_REF_INVALID:payload_hash');
    }
    if (!isHashRef(candidate.result_hash)) {
      return fail('ERR_HASH_REF_INVALID:result_hash');
    }
  }

  const derivedReceiptId = deriveReceiptId(candidate);
  if (candidate.receipt_id !== derivedReceiptId) {
    return fail('ERR_RECEIPT_ID_MISMATCH');
  }

  const trustRoot = trustRoots[candidate.trust_root_id as string];
  if (!trustRoot) {
    return fail('ERR_TRUST_ROOT_UNKNOWN');
  }
  const keyValue = trustRoot[candidate.signing_key_id as string];
  if (!keyValue) {
    return fail('ERR_SIGNING_KEY_UNKNOWN');
  }

  const publicKey = resolvePublicKey(candidate, trustRoots);
  if (!publicKey) {
    return fail('ERR_PUBLIC_KEY_INVALID');
  }

  if (String(candidate.signature).length !== 86) {
    return fail('ERR_SIGNATURE_INVALID');
  }

  const signatureBytes = decodeBase64Url(String(candidate.signature));
  if (signatureBytes.length !== 64) {
    return fail('ERR_SIGNATURE_INVALID');
  }

  const unsigned = { ...candidate };
  delete unsigned.signature;

  const canonicalBytes = canonicalizeJsonToBytes(unsigned);
  const digestBytes = new Uint8Array(createHash('sha256').update(canonicalBytes).digest());
  const valid = ed.verify(signatureBytes, digestBytes, publicKey);

  if (!valid) {
    return fail('ERR_SIGNATURE_INVALID');
  }

  return { ok: true, code: 'OK' };
}
