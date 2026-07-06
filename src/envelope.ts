import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';
import { Buffer } from 'node:buffer';
import { type KeyProvider, CryptoError } from './key-provider.js';

// AES-256-GCM parameters (spec §4).
const ALGORITHM = 'aes-256-gcm';
export const DEK_LENGTH = 32; // 256-bit data encryption key
export const NONCE_LENGTH = 12; // 96-bit GCM nonce, fresh per encryption op
export const TAG_LENGTH = 16; // 128-bit GCM auth tag

/**
 * On-disk layout for a GCM blob: nonce(12) ‖ ciphertext ‖ tag(16).
 * Used for both the secret ciphertext and the wrapped DEK.
 */
function packGcm(nonce: Buffer, ciphertext: Buffer, tag: Buffer): Buffer {
  return Buffer.concat([nonce, ciphertext, tag]);
}

interface UnpackedGcm {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

function unpackGcm(blob: Buffer): UnpackedGcm {
  if (blob.length < NONCE_LENGTH + TAG_LENGTH) {
    throw new CryptoError('Ciphertext too short to contain nonce and tag.');
  }
  const nonce = blob.subarray(0, NONCE_LENGTH);
  const tag = blob.subarray(blob.length - TAG_LENGTH);
  const ciphertext = blob.subarray(NONCE_LENGTH, blob.length - TAG_LENGTH);
  return { nonce, ciphertext, tag };
}

/**
 * Encrypt `plaintext` under a fresh DEK with AES-256-GCM.
 * `aad` (the secret id) is bound into the GCM tag of the data ciphertext, so
 * a ciphertext can only be decrypted in the context of its own record.
 */
function aesGcmEncrypt(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  const nonce = randomBytes(NONCE_LENGTH); // fresh nonce per op (spec §4)
  const cipher = createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_LENGTH,
  });
  if (aad !== undefined) {
    cipher.setAAD(aad);
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return packGcm(nonce, ciphertext, tag);
}

function aesGcmDecrypt(key: Buffer, blob: Buffer, aad?: Buffer): Buffer {
  const { nonce, ciphertext, tag } = unpackGcm(blob);
  const decipher = createDecipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_LENGTH,
  });
  if (aad !== undefined) {
    decipher.setAAD(aad);
  }
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // GCM auth failure: wrong key, tampered ciphertext/tag/dek, or wrong AAD.
    // Never surface crypto internals or the plaintext in the error.
    throw new CryptoError('Decryption failed: authentication check did not pass.');
  }
}

/** Result of encrypting one secret with envelope encryption. */
export interface EncryptedSecret {
  /** nonce(12) ‖ ciphertext ‖ tag(16) — the encrypted secret value. */
  ciphertext: Buffer;
  /** The DEK, itself AES-256-GCM-encrypted under the KEK (same packed layout). */
  dekWrapped: Buffer;
  /** Version of the KEK that wrapped `dekWrapped`, for future rotation. */
  keyVersion: number;
}

/** Input for decrypting one secret. */
export interface EncryptedSecretInput {
  ciphertext: Buffer;
  dekWrapped: Buffer;
  keyVersion: number;
  /** Must equal the AAD used at encryption time (the secret id). */
  aad: string;
}

/**
 * Envelope-encrypt a secret value (spec §4):
 *   1. generate a fresh 32-byte DEK from the CSPRNG,
 *   2. encrypt the plaintext with the DEK (AES-256-GCM), AAD = secret id,
 *   3. wrap (encrypt) the DEK with the current KEK (AES-256-GCM).
 *
 * @param plaintext the real secret value (e.g. an upstream API key)
 * @param aad       the secret's id — binds the ciphertext to its record
 */
export function encryptSecret(
  keyProvider: KeyProvider,
  plaintext: string,
  aad: string,
): EncryptedSecret {
  if (typeof plaintext !== 'string') {
    throw new CryptoError('Plaintext to encrypt must be a string.');
  }
  const keyVersion = keyProvider.currentKeyVersion();
  const kek = keyProvider.getKek(keyVersion);

  const dek = randomBytes(DEK_LENGTH); // fresh DEK per secret (spec §4)
  const aadBuf = Buffer.from(aad, 'utf8');
  // A mutable copy of the plaintext so we can wipe it after use (the input
  // string itself is immutable and cannot be zeroed — a JS limitation).
  const plaintextBuf = Buffer.from(plaintext, 'utf8');

  try {
    const ciphertext = aesGcmEncrypt(dek, plaintextBuf, aadBuf);
    // The wrapped DEK is not bound to the secret id — the data ciphertext
    // already is, and re-wrapping the DEK during KEK rotation must not depend
    // on the id.
    const dekWrapped = aesGcmEncrypt(kek, dek);
    return { ciphertext, dekWrapped, keyVersion };
  } finally {
    // Zero the DEK and the plaintext copy on EVERY path, including if an
    // aesGcmEncrypt call throws — no key/secret material lingers in memory.
    dek.fill(0);
    plaintextBuf.fill(0);
  }
}

/**
 * Reverse of {@link encryptSecret}. Unwraps the DEK with the KEK of the
 * recorded `keyVersion`, then decrypts the ciphertext with AAD = secret id.
 * Throws {@link CryptoError} on any authentication failure (tamper, wrong AAD,
 * wrong key).
 */
export function decryptSecret(
  keyProvider: KeyProvider,
  input: EncryptedSecretInput,
): string {
  const kek = keyProvider.getKek(input.keyVersion);

  const dek = aesGcmDecrypt(kek, input.dekWrapped);
  try {
    if (dek.length !== DEK_LENGTH) {
      throw new CryptoError('Unwrapped DEK has an invalid length.');
    }
    const aadBuf = Buffer.from(input.aad, 'utf8');
    const plaintext = aesGcmDecrypt(dek, input.ciphertext, aadBuf);
    return plaintext.toString('utf8');
  } finally {
    dek.fill(0);
  }
}
