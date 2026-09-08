import {
  generateMLKEMKeyPair,
  encapsulateSharedSecret,
  decapsulateSharedSecret,
} from "./mlKem.js";

function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

export function runMLKEMSelfTest() {
  console.log("Starting ML-KEM-768 self-test...");

  // Bob generates his key pair.
  const bob = generateMLKEMKeyPair();

  // Alice uses Bob's public key.
  const { cipherText, sharedSecret: aliceSecret } =
    encapsulateSharedSecret(bob.publicKey);

  // Bob uses his private key.
  const bobSecret = decapsulateSharedSecret(
    cipherText,
    bob.secretKey
  );

  const passed = bytesEqual(aliceSecret, bobSecret);

  if (!passed) {
    throw new Error("ML-KEM-768 self-test FAILED.");
  }

  console.log("ML-KEM-768 self-test PASSED.");
  console.log("Public key length:", bob.publicKey.length);
  console.log("Secret key length:", bob.secretKey.length);
  console.log("Ciphertext length:", cipherText.length);
  console.log("Shared secret length:", aliceSecret.length);

  return {
    passed,
    publicKeyLength: bob.publicKey.length,
    secretKeyLength: bob.secretKey.length,
    cipherTextLength: cipherText.length,
    sharedSecretLength: aliceSecret.length,
  };
}
