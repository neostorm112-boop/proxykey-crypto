# proxykey-crypto

The envelope-encryption module that [proxykey](https://proxykey.org/en/) uses
to store API keys at rest — published in full, tests included, for
transparency.

proxykey is a credential proxy: you store a real provider key once, and your
apps and AI agents authenticate with revocable passes (`vlt_…`) instead. This
repo is the exact cryptographic core that protects the stored originals.

## What it implements

- **Envelope encryption**: each secret gets its own data-encryption key
  (DEK); the secret is encrypted with **AES-256-GCM**, with the secret's id
  as AAD (a ciphertext cannot be silently re-attached to another record).
- The DEK is wrapped by a master key (**KEK**) supplied via the process
  environment (`VAULT_MASTER_KEY`) — the KEK never touches the database.
- A `KeyProvider` abstraction with a `key_version` field wired for future
  KEK rotation.
- DEK buffers are **zeroed after use**; decryption happens in memory per
  request, plaintext is never cached or logged.

## Honest scope

Two caveats we state plainly (the same way we do on the
[security page](https://proxykey.org/en/security/)):

1. **Open code is a transparency gesture, not proof.** You can review the
   scheme and its tests, but this repo cannot cryptographically prove that
   the deployed service runs exactly this code.
2. **This scheme does not protect against a fully compromised server or a
   malicious operator.** A credential proxy must decrypt the key to inject
   it into upstream requests, so whoever holds the ciphertexts *and* the KEK
   *and* the code can recover plaintexts. That is an architectural property
   of every hosted product in this class; our threat model spells out what
   is and is not covered, and how to cap the residual risk with scoped
   provider keys: <https://proxykey.org/en/security/>

## Use

```ts
import { EnvKeyProvider, encryptSecret, decryptSecret } from './src/index.js';

const kek = new EnvKeyProvider(); // reads VAULT_MASTER_KEY from the environment
const box = encryptSecret(kek, secretId, 'sk-real-key');
// box: { ciphertext, dekWrapped, keyVersion } — safe to store
// (nonce and auth tag are packed inside each buffer: nonce ‖ ct ‖ tag)
const plain = decryptSecret(kek, secretId, box); // in-memory, per request
```

```bash
npm install
npm test        # 18 tests: roundtrip, AAD binding, tamper detection, zeroing
npm run build
```

## License

MIT. Reuse it, audit it, or build your own credential proxy on top — the
[how-it-works write-up](https://proxykey.org/en/blog/what-is-api-key-proxy/)
covers the surrounding architecture.
