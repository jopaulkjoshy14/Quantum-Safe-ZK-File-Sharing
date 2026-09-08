import {
  generateMasterKey,
  generatePasswordSalt,
  deriveKEK,
  wrapMasterKey,
  base64ToBytes,
} from "./crypto.js";

import {
  generateMLKEMKeyPair,
} from "./mlKem.js";

import {
  wrapMLKEMSecretKey,
  unwrapMLKEMSecretKey,
} from "./keyProtection.js";

async function testMasterKeyWrapping(masterKey, password) {
  const salt = generatePasswordSalt();

  const kek = await deriveKEK(password, salt);

  const {
    wrappedMasterKey,
    masterKeyIV,
  } = await wrapMasterKey(masterKey, kek);

  const recoveredMasterKey = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(masterKeyIV),
    },
    kek,
    base64ToBytes(wrappedMasterKey)
  );

  const recovered = new Uint8Array(recoveredMasterKey);

  if (recovered.length !== masterKey.length) {
    throw new Error("Master Key recovery failed.");
  }

  for (let i = 0; i < masterKey.length; i++) {
    if (recovered[i] !== masterKey[i]) {
      throw new Error("Recovered Master Key does not match.");
    }
  }

  return {
    passwordKdf: true,
    masterKeyWrapping: true,
  };
}

async function testMLKEMProtection(masterKey) {
  const {
    publicKey,
    secretKey,
  } = generateMLKEMKeyPair();

  const {
    wrappedMlKemPrivateKey,
    privateKeyIV,
  } = await wrapMLKEMSecretKey(
    masterKey,
    secretKey
  );

  const recoveredSecretKey = await unwrapMLKEMSecretKey(
    masterKey,
    wrappedMlKemPrivateKey,
    privateKeyIV
  );

  if (recoveredSecretKey.length !== secretKey.length) {
    throw new Error("ML-KEM secret key recovery failed.");
  }

  for (let i = 0; i < secretKey.length; i++) {
    if (recoveredSecretKey[i] !== secretKey[i]) {
      throw new Error(
        "Recovered ML-KEM secret key does not match."
      );
    }
  }

  return {
    mlKemKeyGeneration: true,
    mlKemSecretKeyProtection: true,
    publicKeyLength: publicKey.length,
    secretKeyLength: secretKey.length,
  };
}

export async function runRegistrationCryptoSelfTest() {
  console.log(
    "Starting registration cryptography self-test..."
  );

  const password = "TestPassword-Only-For-Crypto-Test";

  /*
   * Generate the same kind of Master Key used during
   * real registration.
   */
  const masterKey = generateMasterKey();

  /*
   * Test:
   *
   * Password
   *   ↓
   * PBKDF2
   *   ↓
   * KEK
   *   ↓
   * AES-256-GCM
   *   ↓
   * Wrapped Master Key
   */
  const masterKeyResult = await testMasterKeyWrapping(
    masterKey,
    password
  );

  /*
   * Test:
   *
   * Master Key
   *   ↓
   * AES-256-GCM
   *   ↓
   * Wrapped ML-KEM Secret Key
   *   ↓
   * AES-256-GCM decrypt
   *   ↓
   * Original Secret Key
   */
  const mlKemResult = await testMLKEMProtection(
    masterKey
  );

  const result = {
    passed: true,
    ...masterKeyResult,
    ...mlKemResult,
  };

  console.log(
    "Registration cryptography self-test PASSED."
  );

  console.log(
    "Result:",
    result
  );

  return result;
}
