function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(PASSWORD_SALT_LENGTH);

    crypto.pbkdf2(
      password,
      salt,
      PASSWORD_HASH_ITERATIONS,
      PASSWORD_HASH_KEY_LENGTH,
      PASSWORD_HASH_DIGEST,
      (error, hash) => {
        if (error) {
          reject(error);
          return;
        }

        resolve({
          passwordHash: hash.toString("base64"),
          passwordKdfSalt: salt.toString("base64"),
          passwordKdfParams: {
            algorithm: "PBKDF2-HMAC-SHA-256",
            iterations: PASSWORD_HASH_ITERATIONS,
            keyLength: PASSWORD_HASH_KEY_LENGTH,
          },
        });
      }
    );
  });
}
