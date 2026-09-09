import {
  generateMasterKey,
  generatePasswordSalt,
  deriveKEK,
  wrapMasterKey,
  getPasswordKdfParams,
  bytesToBase64,
} from "./crypto.js";

import { generateMLKEMKeyPair } from "./mlKem.js";

import { wrapMLKEMSecretKey } from "./keyProtection.js";

/**
 * Prepare all cryptographic material required for user registration.
 *
 * IMPORTANT:
 * The returned object contains only protected/serializable material
 * intended for transmission to the backend.
 *
 * Plaintext Master Key and ML-KEM secret key remain in browser memory
 * and are never included in the returned registration payload.
 */
export async function prepareRegistrationCrypto(password) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password is required.");
  }

  /*
   * ------------------------------------------------------------
   * 1. Generate random Master Key
   * ------------------------------------------------------------
   *
   * This key is independent of the user's password.
   */
  const masterKey = generateMasterKey();

  /*
   * ------------------------------------------------------------
   * 2. Derive KEK from password
   * ------------------------------------------------------------
   */
  const passwordSalt = generatePasswordSalt();

  const kek = await deriveKEK(password, passwordSalt);

  /*
   * ------------------------------------------------------------
   * 3. Protect Master Key with KEK
   * ------------------------------------------------------------
   */
  const {
    wrappedMasterKey,
    masterKeyIV,
  } = await wrapMasterKey(masterKey, kek);

  /*
   * ------------------------------------------------------------
   * 4. Generate ML-KEM-768 key pair
   * ------------------------------------------------------------
   */
  const {
    publicKey,
    secretKey,
  } = generateMLKEMKeyPair();

  /*
   * ------------------------------------------------------------
   * 5. Protect ML-KEM secret key with Master Key
   * ------------------------------------------------------------
   */
  const {
    wrappedMlKemPrivateKey,
    privateKeyIV,
  } = await wrapMLKEMSecretKey(masterKey, secretKey);

  /*
   * ------------------------------------------------------------
   * 6. Build backend registration payload
   * ------------------------------------------------------------
   */
  const registrationCrypto = {
    passwordKdfSalt: bytesToBase64(passwordSalt),

    passwordKdfParams: getPasswordKdfParams(),

    wrappedMasterKey,
    masterKeyIV,
    masterKeyVersion: 1,

    mlKemPublicKey: bytesToBase64(publicKey),

    wrappedMlKemPrivateKey,
    privateKeyIV,
  };

  /*
   * ------------------------------------------------------------
   * 7. Best-effort cleanup of sensitive references
   * ------------------------------------------------------------
   *
   * JavaScript garbage collection is not deterministic, so this
   * does NOT guarantee memory erasure.
   *
   * It does ensure this function does not intentionally return
   * plaintext key material.
   * ------------------------------------------------------------
   */

  return registrationCrypto;
}
