export const KORZENT_PROTOCOL = 'korzent' as const;
export const KORZENT_PROTOCOL_VERSION = '1.0.0' as const;
export const ZERO_HASH = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as const;

export const ATTEMPT_DENY_CODES = [
  'MISSING_ENV',
  'INVALID_REQUEST',
  'TRUST_ROOT_UNKNOWN',
  'SIGNING_KEY_UNKNOWN',
  'POLICY_MISSING',
  'EPOCH_MISSING',
  'INTERNAL_ERROR',
] as const;

export type HashRef = `sha256:${string}`;
export type Decision = 'ALLOW' | 'DENY';
export type AttemptDenyCode = (typeof ATTEMPT_DENY_CODES)[number];

export interface ReceiptCommonV1 {
  protocol: typeof KORZENT_PROTOCOL;
  protocol_version: typeof KORZENT_PROTOCOL_VERSION;
  schema_hash: HashRef;
  trust_root_id: string;
  receipt_id: HashRef;
  intent_hash: HashRef;
  policy_pack_hash: HashRef;
  decision: Decision;
  inputs_snapshot_hash: HashRef;
  epoch_hash: HashRef;
  timestamp_utc: string;
  signing_key_id: string;
  signature: string;
}

export interface EvaluateReceiptV1 extends ReceiptCommonV1 {}

export interface AttemptReceiptV1 extends ReceiptCommonV1 {
  decision: 'DENY';
  deny_code: AttemptDenyCode;
  deny_message?: string;
}

export interface ExecutionReceiptV1 extends ReceiptCommonV1 {
  decision: 'ALLOW';
  parent_receipt_id: HashRef;
  action_driver: string;
  payload_hash: HashRef;
  result_hash: HashRef;
}

export type ReceiptV1 = EvaluateReceiptV1 | ExecutionReceiptV1 | AttemptReceiptV1;

export type UnsignedEvaluateReceiptV1 = Omit<EvaluateReceiptV1, 'signature' | 'receipt_id'>;
export type UnsignedAttemptReceiptV1 = Omit<AttemptReceiptV1, 'signature' | 'receipt_id'>;
export type UnsignedExecutionReceiptV1 = Omit<ExecutionReceiptV1, 'signature' | 'receipt_id'>;
export type UnsignedReceiptV1 = UnsignedEvaluateReceiptV1 | UnsignedExecutionReceiptV1 | UnsignedAttemptReceiptV1;

export type TrustRootKey = string | Uint8Array;

export interface TrustRoots {
  [trust_root_id: string]: {
    [signing_key_id: string]: TrustRootKey;
  };
}

export interface VerifyResult {
  ok: boolean;
  code: string;
}
