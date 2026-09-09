import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

/**
 * Generate an ML-KEM-768 key pair.
 *
 * Returns:
 * - publicKey: safe to share with other users
 * - secretKey: must remain protected by the user's Master Key
 */
export function generateMLKEMKeyPair() {
  const { publicKey, secretKey } = ml_kem768.keygen();

  return {
    publicKey,
    secretKey,
  };
}

/**
 * Encapsulate a shared secret using the recipient's public key.
 *
 * Used by the sender when sharing a file.
 *
 * Returns:
 * - ciphertext: sent to the recipient through the backend
 * - sharedSecret: NEVER sent to the backend
 */
export function encapsulateSharedSecret(recipientPublicKey) {
  const { cipherText, sharedSecret } =
    ml_kem768.encapsulate(recipientPublicKey);

  return {
    cipherText,
    sharedSecret,
  };
}

/**
 * Decapsulate the shared secret using the recipient's secret key.
 *
 * Used by the recipient when opening a shared file.
 */
export function decapsulateSharedSecret(cipherText, secretKey) {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
