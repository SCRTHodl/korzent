import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { canonicalizeJsonToBytes } from './canonical.js';
import { sha256Ref } from './hash.js';
import type { UnsignedReceiptV1 } from './types.js';

const require = createRequire(import.meta.url);

const ed = require('../../services/action-gateway/node_modules/@noble/ed25519/index.js') as {
  etc: { sha512Sync: (...messages: Uint8Array[]) => Uint8Array };
  getPublicKey: (privateKey: Uint8Array) => Uint8Array;
  sign: (message: Uint8Array, privateKey: Uint8Array) => Uint8Array;
};

ed.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => {
  const hash = createHash('sha512');
  for (const message of messages) {
    hash.update(message);
  }
  return new Uint8Array(hash.digest());
};

function toRecord(unsignedReceipt: UnsignedReceiptV1 | Record<string, unknown>): Record<string, unknown> {
  return { ...(unsignedReceipt as Record<string, unknown>) };
}

export function deriveReceiptId(unsignedReceipt: UnsignedReceiptV1 | Record<string, unknown>): `sha256:${string}` {
  const candidate = toRecord(unsignedReceipt);
  delete candidate.signature;
  delete candidate.receipt_id;
  return sha256Ref(canonicalizeJsonToBytes(candidate));
}

export function derivePublicKey(privateKey: Uint8Array): Uint8Array {
  return ed.getPublicKey(privateKey);
}

export function signReceipt(unsignedReceipt: UnsignedReceiptV1 | Record<string, unknown>, privateKey: Uint8Array): string {
  const candidate = toRecord(unsignedReceipt);
  delete candidate.signature;

  const canonicalBytes = canonicalizeJsonToBytes(candidate);
  const digestBytes = new Uint8Array(createHash('sha256').update(canonicalBytes).digest());
  const signatureBytes = ed.sign(digestBytes, privateKey);
  return Buffer.from(signatureBytes).toString('base64url');
}
