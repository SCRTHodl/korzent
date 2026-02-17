import embeddedSchema from '../receipt.schema.json';
import { canonicalizeJsonToBytes } from './canonical.js';
import { sha256Ref } from './hash.js';

export const KORZENT_V1_SCHEMA_HASH = 'sha256:103e0121f3f5b71b9a6a8489feb7159c0e99518f1bb0f5fbee6e1709ec16f40f';

export function computeSchemaHashFromEmbeddedSchema(): string {
  return sha256Ref(canonicalizeJsonToBytes(embeddedSchema));
}

export { embeddedSchema as KORZENT_V1_RECEIPT_SCHEMA };
