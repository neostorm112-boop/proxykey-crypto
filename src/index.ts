export {
  type KeyProvider,
  EnvKeyProvider,
  CryptoError,
  KEK_LENGTH,
} from './key-provider.js';

export {
  encryptSecret,
  decryptSecret,
  type EncryptedSecret,
  type EncryptedSecretInput,
  DEK_LENGTH,
  NONCE_LENGTH,
  TAG_LENGTH,
} from './envelope.js';
