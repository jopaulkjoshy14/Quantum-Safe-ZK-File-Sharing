const MASTER_KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 16; // 128 bits
const IV_LENGTH = 12; // 96 bits

const PBKDF2_ITERATIONS = 310000;
const PBKDF2_KEY_LENGTH = 256;
const PBKDF2_HASH = "SHA-256";

const AES_ALGORITHM = "AES-GCM";

/**
 * Convert bytes to Base64.
 */
export function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

/**
 * Convert Base64 to bytes.
 */
export function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * Generate a cryptographically secure random Master Key.
 *
 * The Master Key is generated independently from the password.
 */
export function generateMasterKey() {
  return crypto.getRandomValues(new Uint8Array(MASTER_KEY_LENGTH));
}

/**
 * Generate a cryptographically secure PBKDF2 salt.
 */
export function generatePasswordSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Generate a cryptographically secure AES-GCM IV.
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

/**
 * Derive a Key Encryption Key (KEK) from the user's password.
 *
 * Password → PBKDF2-HMAC-SHA-256 → KEK
 */
export async function deriveKEK(password, salt) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password is required.");
  }

  if (!(salt instanceof Uint8Array)) {
    throw new Error("PBKDF2 salt must be a Uint8Array.");
  }

  const passwordBytes = new TextEncoder().encode(password);

  const passwordKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    passwordKey,
    {
      name: AES_ALGORITHM,
      length: PBKDF2_KEY_LENGTH,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wrap the Master Key using the password-derived KEK.
 *
 * Master Key → AES-256-GCM → Wrapped Master Key
 */
export async function wrapMasterKey(masterKey, kek) {
  if (!(masterKey instanceof Uint8Array)) {
    throw new Error("Master Key must be a Uint8Array.");
  }

  if (!(kek instanceof CryptoKey)) {
    throw new Error("KEK must be a CryptoKey.");
  }

  const iv = generateIV();

  const wrappedMasterKey = await crypto.subtle.encrypt(
    {
      name: AES_ALGORITHM,
      iv,
    },
    kek,
    masterKey
  );

  return {
    wrappedMasterKey: bytesToBase64(new Uint8Array(wrappedMasterKey)),
    masterKeyIV: bytesToBase64(iv),
  };
}

/**
 * Export the cryptographic parameters used by the client.
 */
export function getPasswordKdfParams() {
  return {
    algorithm: "PBKDF2-HMAC-SHA-256",
    iterations: PBKDF2_ITERATIONS,
    keyLength: 256,
  };
}
