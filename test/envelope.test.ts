import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import {
  EnvKeyProvider,
  CryptoError,
  encryptSecret,
  decryptSecret,
  NONCE_LENGTH,
  TAG_LENGTH,
} from '../src/index.js';

// A deterministic, valid 32-byte KEK for tests (base64 of 32 zero-ish bytes).
const VALID_KEK_B64 = randomBytes(32).toString('base64');

function makeProvider(b64 = VALID_KEK_B64): EnvKeyProvider {
  return new EnvKeyProvider({ VAULT_MASTER_KEY: b64 });
}

const SECRET_ID = '018f9d3c-0000-7000-8000-000000000001';
const PLAINTEXT = 'sk-test-1234567890-REAL-UPSTREAM-KEY';

describe('EnvKeyProvider', () => {
  it('rejects a missing VAULT_MASTER_KEY with a clear error', () => {
    expect(() => new EnvKeyProvider({})).toThrow(CryptoError);
    expect(() => new EnvKeyProvider({})).toThrow(/VAULT_MASTER_KEY/);
  });

  it('rejects an empty VAULT_MASTER_KEY', () => {
    expect(() => new EnvKeyProvider({ VAULT_MASTER_KEY: '' })).toThrow(
      CryptoError,
    );
  });

  it('rejects a malformed (wrong-length) VAULT_MASTER_KEY', () => {
    // 16 bytes base64 -> not 32 bytes
    const short = randomBytes(16).toString('base64');
    expect(() => new EnvKeyProvider({ VAULT_MASTER_KEY: short })).toThrow(
      /expected 32/,
    );
  });

  it('rejects non-base64 garbage that decodes to the wrong length', () => {
    expect(() => new EnvKeyProvider({ VAULT_MASTER_KEY: 'not-a-real-key' })).toThrow(
      CryptoError,
    );
  });

  it('accepts a valid 32-byte base64 key', () => {
    expect(() => makeProvider()).not.toThrow();
    expect(makeProvider().currentKeyVersion()).toBe(1);
  });
});

describe('envelope encryption roundtrip', () => {
  it('decrypts back to the original plaintext', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const dec = decryptSecret(kp, { ...enc, aad: SECRET_ID });
    expect(dec).toBe(PLAINTEXT);
  });

  it('handles empty-string plaintext', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, '', SECRET_ID);
    expect(decryptSecret(kp, { ...enc, aad: SECRET_ID })).toBe('');
  });

  it('handles unicode plaintext', () => {
    const kp = makeProvider();
    const text = 'токен-🔑-secret';
    const enc = encryptSecret(kp, text, SECRET_ID);
    expect(decryptSecret(kp, { ...enc, aad: SECRET_ID })).toBe(text);
  });

  it('records the current key version', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    expect(enc.keyVersion).toBe(1);
  });

  it('produces the packed nonce||ct||tag layout', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    // ciphertext blob is at least nonce + tag; the encrypted plaintext sits between.
    expect(enc.ciphertext.length).toBeGreaterThan(NONCE_LENGTH + TAG_LENGTH);
    expect(enc.dekWrapped.length).toBe(NONCE_LENGTH + 32 + TAG_LENGTH);
  });
});

describe('nonce / ciphertext uniqueness', () => {
  it('two encryptions of the same plaintext differ in nonce and ciphertext', () => {
    const kp = makeProvider();
    const a = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const b = encryptSecret(kp, PLAINTEXT, SECRET_ID);

    // Whole blobs differ.
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
    // Nonces (first 12 bytes) differ.
    const nonceA = a.ciphertext.subarray(0, NONCE_LENGTH);
    const nonceB = b.ciphertext.subarray(0, NONCE_LENGTH);
    expect(nonceA.equals(nonceB)).toBe(false);
    // Fresh DEK each time -> wrapped DEKs differ too.
    expect(a.dekWrapped.equals(b.dekWrapped)).toBe(false);

    // Both still decrypt correctly.
    expect(decryptSecret(kp, { ...a, aad: SECRET_ID })).toBe(PLAINTEXT);
    expect(decryptSecret(kp, { ...b, aad: SECRET_ID })).toBe(PLAINTEXT);
  });
});

describe('tamper detection', () => {
  it('throws when a byte in the auth tag is flipped', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const tampered = Buffer.from(enc.ciphertext);
    // last TAG_LENGTH bytes are the tag; flip a bit in the last byte.
    tampered[tampered.length - 1] ^= 0x01;
    expect(() =>
      decryptSecret(kp, { ...enc, ciphertext: tampered, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });

  it('throws when a byte in the ciphertext body is flipped', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const tampered = Buffer.from(enc.ciphertext);
    // a byte inside the ciphertext body (just past the nonce).
    tampered[NONCE_LENGTH] ^= 0x01;
    expect(() =>
      decryptSecret(kp, { ...enc, ciphertext: tampered, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });

  it('throws when a byte in the wrapped DEK is flipped', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const tampered = Buffer.from(enc.dekWrapped);
    tampered[tampered.length - 1] ^= 0x01;
    expect(() =>
      decryptSecret(kp, { ...enc, dekWrapped: tampered, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });

  it('throws when the nonce is altered', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    const tampered = Buffer.from(enc.ciphertext);
    tampered[0] ^= 0x01;
    expect(() =>
      decryptSecret(kp, { ...enc, ciphertext: tampered, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });
});

describe('AAD binding', () => {
  it('throws when decrypting with a different AAD (wrong secret id)', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    expect(() =>
      decryptSecret(kp, { ...enc, aad: 'different-secret-id' }),
    ).toThrow(CryptoError);
  });

  it('throws when decrypting with a KEK from a different provider', () => {
    const kp = makeProvider();
    const other = makeProvider(randomBytes(32).toString('base64'));
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    expect(() =>
      decryptSecret(other, { ...enc, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });
});

describe('key version handling', () => {
  it('throws when asked to decrypt with an unknown key version', () => {
    const kp = makeProvider();
    const enc = encryptSecret(kp, PLAINTEXT, SECRET_ID);
    expect(() =>
      decryptSecret(kp, { ...enc, keyVersion: 999, aad: SECRET_ID }),
    ).toThrow(CryptoError);
  });
});
