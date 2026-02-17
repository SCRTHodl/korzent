#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyReceipt } from '../src/verify.js';
import type { TrustRoots } from '../src/types.js';

interface VerifyArgs {
  receiptPath: string;
  trustRootValue: string;
}

function usage(): string {
  return 'Usage: korzent verify <receipt.json> --trust-root <pubkey-or-file>';
}

function readTextValue(valueOrPath: string): string {
  const absolute = resolve(process.cwd(), valueOrPath);
  if (existsSync(absolute)) {
    const lines = readFileSync(absolute, 'utf-8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
    return lines[0] ?? '';
  }
  return valueOrPath.trim();
}

function parseVerifyArgs(argv: string[]): VerifyArgs {
  if (argv.length < 4 || argv[0] !== 'verify') {
    throw new Error(`ERR_CLI_BAD_ARGS: ${usage()}`);
  }

  const receiptPath = argv[1];
  let trustRootValue = '';

  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--trust-root') {
      trustRootValue = argv[i + 1] ?? '';
      i += 1;
    }
  }

  if (!receiptPath) {
    throw new Error('ERR_CLI_BAD_ARGS: missing receipt path');
  }

  if (!trustRootValue) {
    throw new Error('ERR_CLI_BAD_ARGS: --trust-root is required');
  }

  return { receiptPath, trustRootValue };
}

function loadReceipt(receiptPath: string): Record<string, unknown> {
  const absolute = resolve(process.cwd(), receiptPath);
  if (!existsSync(absolute)) {
    throw new Error(`ERR_CLI_RECEIPT_NOT_FOUND: ${receiptPath}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(absolute, 'utf-8'));
  } catch (err) {
    throw new Error(`ERR_CLI_RECEIPT_PARSE: ${(err as Error).message}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('ERR_CLI_RECEIPT_MALFORMED');
  }

  return parsed as Record<string, unknown>;
}

function buildTrustRoots(receipt: Record<string, unknown>, trustRootValue: string): TrustRoots {
  const trustRootId = receipt.trust_root_id;
  const signingKeyId = receipt.signing_key_id;

  if (typeof trustRootId !== 'string' || trustRootId.length === 0) {
    throw new Error('ERR_CLI_TRUST_ROOT_ID_MISSING');
  }
  if (typeof signingKeyId !== 'string' || signingKeyId.length === 0) {
    throw new Error('ERR_CLI_SIGNING_KEY_ID_MISSING');
  }

  const publicKey = readTextValue(trustRootValue);
  if (!publicKey) {
    throw new Error('ERR_CLI_TRUST_ROOT_VALUE_EMPTY');
  }

  return {
    [trustRootId]: {
      [signingKeyId]: publicKey,
    },
  };
}

function printInvalid(code: string): never {
  process.stdout.write(`INVALID ${code}\n`);
  process.exit(1);
}

function main(): void {
  try {
    const args = parseVerifyArgs(process.argv.slice(2));
    const receipt = loadReceipt(args.receiptPath);
    const trustRoots = buildTrustRoots(receipt, args.trustRootValue);
    const result = verifyReceipt(receipt, trustRoots);

    if (!result.ok) {
      printInvalid(result.code);
    }

    process.stdout.write(`VALID ${result.code}\n`);
  } catch (err) {
    printInvalid((err as Error).message);
  }
}

main();
