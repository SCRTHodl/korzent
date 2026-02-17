const textEncoder = new TextEncoder();

function serializeCanonical(value: unknown, path: string): string {
  if (value === null) return 'null';

  const valueType = typeof value;
  if (valueType === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (valueType === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`FAIL-CLOSED: non-finite number at ${path}`);
    }
    return JSON.stringify(value);
  }

  if (valueType === 'string') {
    return JSON.stringify(value);
  }

  if (valueType === 'undefined' || valueType === 'bigint' || valueType === 'function' || valueType === 'symbol') {
    throw new Error(`FAIL-CLOSED: unsupported JSON type at ${path}`);
  }

  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.prototype.hasOwnProperty.call(value, i)) {
        throw new Error(`FAIL-CLOSED: sparse array at ${path}[${i}]`);
      }
      items.push(serializeCanonical(value[i], `${path}[${i}]`));
    }
    return '[' + items.join(',') + ']';
  }

  const objectValue = value as Record<string, unknown>;
  const keys = Object.keys(objectValue).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const pairs: string[] = [];

  for (const key of keys) {
    const child = objectValue[key];
    if (typeof child === 'undefined' || typeof child === 'bigint' || typeof child === 'function' || typeof child === 'symbol') {
      throw new Error(`FAIL-CLOSED: unsupported object value at ${path}.${key}`);
    }
    pairs.push(JSON.stringify(key) + ':' + serializeCanonical(child, `${path}.${key}`));
  }

  return '{' + pairs.join(',') + '}';
}

export function canonicalizeJsonToBytes(value: unknown): Uint8Array {
  const canonical = serializeCanonical(value, '$');
  return textEncoder.encode(canonical);
}
