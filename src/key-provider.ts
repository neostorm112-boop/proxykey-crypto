import { Buffer } from 'node:buffer';

/**
 * The master key (KEK) is 32 raw bytes. It wraps per-secret DEKs; it never
 * encrypts secret plaintext directly (spec §4).
 */
export const KEK_LENGTH = 32;

/**
 * Abstraction over the source of the master key (KEK), so a KMS-backed
 * provider can be dropped in later without touching call sites (spec §4).
 *
 * `keyVersion` supports future KEK rotation: the wrapped DEK carries the
 * version of the KEK that wrapped it, so a rotation can re-wrap DEKs
 * (re-encrypt the small DEK) without re-encrypting the secret data itself.
 */
export interface KeyProvider {
  /** Return the raw 32-byte KEK for the given version. */
  getKek(keyVersion: number): Buffer;
  /** The version to use for new encryptions. */
  currentKeyVersion(): number;
}

export class CryptoError extends Error {
  override name = 'CryptoError';
}

/**
 * Reads a base64-encoded 32-byte KEK from an environment variable
 * (default `VAULT_MASTER_KEY`). Fails loudly on a missing or malformed key.
 */
export class EnvKeyProvider implements KeyProvider {
  readonly #kek: Buffer;
  readonly #version: number;

  /**
   * @param env       environment object to read from (defaults to process.env)
   * @param varName   name of the variable holding the base64 KEK
   * @param keyVersion version tag for keys wrapped by this provider (default 1)
   */
  constructor(
    env: NodeJS.ProcessEnv = process.env,
    varName = 'VAULT_MASTER_KEY',
    keyVersion = 1,
  ) {
    const raw = env[varName];
    if (raw === undefined || raw === '') {
      throw new CryptoError(
        `Missing master key: environment variable ${varName} is not set. ` +
          `Generate one with: openssl rand -base64 32`,
      );
    }

    let decoded: Buffer;
    try {
      decoded = Buffer.from(raw, 'base64');
    } catch {
      // Buffer.from never throws for base64, but keep this defensive.
      throw new CryptoError(
        `Malformed master key in ${varName}: value is not valid base64.`,
      );
    }

    // Buffer.from(base64) silently drops invalid trailing chars, so verify the
    // byte length rather than trusting the input string.
    if (decoded.length !== KEK_LENGTH) {
      throw new CryptoError(
        `Malformed master key in ${varName}: decoded to ${decoded.length} bytes, ` +
          `expected ${KEK_LENGTH}. Generate one with: openssl rand -base64 32`,
      );
    }

    this.#kek = decoded;
    this.#version = keyVersion;
  }

  getKek(keyVersion: number): Buffer {
    if (keyVersion !== this.#version) {
      throw new CryptoError(
        `No master key available for key_version=${keyVersion} ` +
          `(this provider holds version ${this.#version}).`,
      );
    }
    return this.#kek;
  }

  currentKeyVersion(): number {
    return this.#version;
  }
}
