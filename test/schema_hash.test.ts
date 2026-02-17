import { describe, expect, it } from '../../services/action-gateway/node_modules/vitest/dist/index.js';
import { computeSchemaHashFromEmbeddedSchema, KORZENT_V1_SCHEMA_HASH } from '../src/schema.js';

describe('KORZENT_V1_SCHEMA_HASH', () => {
  it('is stable across repeated computations', () => {
    const h1 = computeSchemaHashFromEmbeddedSchema();
    const h2 = computeSchemaHashFromEmbeddedSchema();
    expect(h1).toBe(h2);
  });

  it('matches locked constant exactly', () => {
    const computed = computeSchemaHashFromEmbeddedSchema();
    expect(computed).toBe(KORZENT_V1_SCHEMA_HASH);
  });

  it('uses sha256:<lower-hex> encoding', () => {
    expect(KORZENT_V1_SCHEMA_HASH).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
