import {
  encryptFile,
  decryptFile,
} from "./fileCrypto.js";

import {
  wrapOwnerFEK,
  unwrapOwnerFEK,
} from "./keyWrapping.js";

import {
  generateMasterKey,
} from "./crypto.js";

/**
 * Convert a Uint8Array to a UTF-8 string.
 */
function bytesToText(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Create a deterministic test File.
 *
 * This is test data only and is never uploaded.
 */
function createTestFile() {
  const content =
    "QSZKFSS Frozen V1 file encryption test.";

  return new File(
    [content],
    "crypto-test.txt",
    {
      type: "text/plain",
    }
  );
}

/**
 * Run the complete File Encryption + FEK
 * wrapping self-test.
 */
export async function runFileCryptoSelfTest() {
  console.log(
    "Starting File Crypto self-test..."
  );

  /*
   * Generate a random Master Key.
   */
  const masterKey =
    generateMasterKey();

  if (masterKey.length !== 32) {
    throw new Error(
      "Master Key length test failed."
    );
  }

  /*
   * Create test plaintext.
   */
  const file =
    createTestFile();

  const originalText =
    await file.text();

  /*
   * Encrypt the file.
   *
   * A fresh random FEK is generated internally.
   */
  const {
    encryptedData,
    fek,
    iv,
  } = await encryptFile(file);

  if (fek.length !== 32) {
    throw new Error(
      "FEK length test failed."
    );
  }

  if (iv.length !== 12) {
    throw new Error(
      "File encryption IV length test failed."
    );
  }

  /*
   * Make sure encryption actually changed
   * the plaintext.
   */
  const ciphertextText =
    bytesToText(encryptedData);

  if (
    ciphertextText ===
    originalText
  ) {
    throw new Error(
      "Encryption test failed: ciphertext matches plaintext."
    );
  }

  /*
   * Wrap the FEK using the Master Key-derived
   * Owner FEK-Wrapping Key.
   */
  const {
    wrappedFEK,
    ownerFEKIV,
  } = await wrapOwnerFEK(
    masterKey,
    fek
  );

  if (
    typeof wrappedFEK !== "string" ||
    wrappedFEK.length === 0
  ) {
    throw new Error(
      "FEK wrapping test failed."
    );
  }

  if (
    typeof ownerFEKIV !== "string" ||
    ownerFEKIV.length === 0
  ) {
    throw new Error(
      "FEK wrapping IV test failed."
    );
  }

  /*
   * Recover the FEK.
   */
  const recoveredFEK =
    await unwrapOwnerFEK(
      masterKey,
      wrappedFEK,
      ownerFEKIV
    );

  if (
    recoveredFEK.length !== 32
  ) {
    throw new Error(
      "Recovered FEK length test failed."
    );
  }

  /*
   * Verify that the recovered FEK is
   * identical to the original FEK.
   */
  if (
    recoveredFEK.length !==
    fek.length
  ) {
    throw new Error(
      "Recovered FEK length mismatch."
    );
  }

  for (
    let i = 0;
    i < fek.length;
    i++
  ) {
    if (
      recoveredFEK[i] !==
      fek[i]
    ) {
      throw new Error(
        "Recovered FEK does not match original FEK."
      );
    }
  }

  /*
   * Decrypt using the recovered FEK.
   */
  const decryptedBytes =
    await decryptFile(
      encryptedData,
      recoveredFEK,
      iv
    );

  const decryptedText =
    bytesToText(
      decryptedBytes
    );

  /*
   * Final integrity test.
   */
  if (
    decryptedText !==
    originalText
  ) {
    throw new Error(
      "Decrypted file does not match original plaintext."
    );
  }

  console.log(
    "File Crypto self-test PASSED."
  );

  return {
    passed: true,

    masterKeyLength:
      masterKey.length,

    fekLength:
      fek.length,

    ivLength:
      iv.length,

    encryptedDataLength:
      encryptedData.length,

    wrappedFEKPresent:
      true,

    recoveredFEKMatches:
      true,

    plaintextRecovered:
      decryptedText ===
      originalText,
  };
}
