import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verify.js';
import type { TrustRoots } from '../src/types.js';

type ExpectedVector = {
  file: string;
  kind: 'EVALUATION' | 'EXECUTION' | 'ATTEMPT';
  protocol: string;
  protocol_version: string;
  decision: string;
  schema_hash: string;
  receipt_id: string;
  signature: string;
};

type ExpectedPins = Record<string, ExpectedVector>;

async function loadJson<T>(path: string): Promise<T> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as T;
}

async function loadDemoTrustRoots(): Promise<TrustRoots> {
  const raw = await readFile('examples/demo_pubkey.txt', 'utf8');
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));

  const pubkey = lines[0];
  if (!pubkey) {
    throw new Error('missing demo pubkey');
  }

  return {
    'demo-root': {
      'demo-k1': pubkey,
    },
  };
}

describe('deterministic test vectors', () => {
  it('verifies pinned example receipts', async () => {
    const trustRoots = await loadDemoTrustRoots();
    const expected = await loadJson<ExpectedPins>('test-vectors/vectors.expected.json');

    for (const [name, vec] of Object.entries(expected)) {
      const receipt = await loadJson<Record<string, unknown>>(vec.file);

      const result = verifyReceipt(receipt, trustRoots);
      expect(result, name).toEqual({ ok: true, code: 'OK' });

      expect(receipt.protocol, `${name}:protocol`).toBe(vec.protocol);
      expect(receipt.protocol_version, `${name}:protocol_version`).toBe(vec.protocol_version);
      expect(receipt.schema_hash, `${name}:schema_hash`).toBe(vec.schema_hash);
      expect(receipt.receipt_id, `${name}:receipt_id`).toBe(vec.receipt_id);
      expect(receipt.signature, `${name}:signature`).toBe(vec.signature);
      expect(receipt.decision, `${name}:decision`).toBe(vec.decision);
    }
  });
});
