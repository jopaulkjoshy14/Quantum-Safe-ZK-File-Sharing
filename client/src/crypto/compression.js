const GZIP_FORMAT = "gzip";

async function readStream(stream, maxBytes = Number.POSITIVE_INFINITY) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("Decompressed file exceeds its protected original size.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** Compress file bytes before encryption when gzip reduces their size. */
export async function compressForStorage(file) {
  if (!(file instanceof File)) {
    throw new Error("A valid File object is required for compression.");
  }

  if (typeof CompressionStream === "undefined") {
    throw new Error("This browser does not support gzip compression. Update your browser and try again.");
  }

  const compressed = await readStream(
    file.stream().pipeThrough(new CompressionStream(GZIP_FORMAT))
  );

  return compressed.length < file.size
    ? { bytes: compressed, compression: GZIP_FORMAT }
    : { bytes: new Uint8Array(await file.arrayBuffer()), compression: "none" };
}

/** Restore the original bytes after decrypting a file stored with gzip. */
export async function decompressAfterDownload(bytes, compression, expectedSize) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("Decrypted file data is invalid.");
  }

  if (compression == null || compression === "none") return bytes;
  if (compression !== GZIP_FORMAT) {
    throw new Error("This file uses an unsupported compression format.");
  }
  if (typeof DecompressionStream === "undefined") {
    throw new Error("This browser does not support gzip decompression. Update your browser and try again.");
  }
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0) {
    throw new Error("The protected original file size is invalid.");
  }

  return readStream(
    new Blob([bytes]).stream().pipeThrough(new DecompressionStream(GZIP_FORMAT)),
    expectedSize
  );
}
