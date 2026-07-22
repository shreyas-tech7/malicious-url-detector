/**
 * Client-side file digesting.
 *
 * The /check endpoint deliberately does not accept uploads — see the contract
 * note in `app/check/route.ts`. The file is read in the browser, hashed with
 * WebCrypto, and only the digest, a 64-byte header sample, the filename and
 * the declared MIME type are ever sent. The bytes themselves never leave the
 * device, which is the same posture the URL scanner takes when it refuses to
 * fetch the link it is scoring.
 */

/** Mirrors MAX_HEADER_SAMPLE_BYTES in api/index.py. */
export const HEADER_SAMPLE_BYTES = 64;

/**
 * WebCrypto has no streaming digest, so the whole file has to be resident to
 * hash it. This ceiling keeps a large drop from pinning a tab's memory; it is
 * a browser constraint, not a server one.
 */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

export type FileDigest = {
  name: string;
  size: number;
  /** Browser-declared type. Often empty — the server treats it as a hint. */
  mimeType: string;
  /** Lowercase hex SHA-256 of the full file. */
  sha256: string;
  /** Base64 of the first HEADER_SAMPLE_BYTES bytes, or null for an empty file. */
  headerB64: string | null;
};

/** Thrown for conditions the user can act on, so callers can surface `message`. */
export class DigestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DigestError";
  }
}

const toHex = (buffer: ArrayBuffer): string =>
  Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const toBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

export const formatBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let unit = 0;
  const decimals = () => (value < 10 ? 1 : 0);

  /*
   * Roll over on the rounded value, not the raw one. 1048575 bytes is 1023.999
   * KB, which clears a `value >= 1024` test and then prints as "1024 KB".
   */
  while (Number(value.toFixed(decimals())) >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  return `${value.toFixed(decimals())} ${units[unit]}`;
};

export async function digestFile(file: File): Promise<FileDigest> {
  if (file.size > MAX_FILE_BYTES) {
    throw new DigestError(
      `That file is ${formatBytes(file.size)}. Hashing happens in this tab, so it is capped at ${formatBytes(MAX_FILE_BYTES)}.`,
    );
  }

  // crypto.subtle is only exposed in a secure context. localhost qualifies, as
  // does any https origin, so in practice this fires on a plain-http host.
  if (!globalThis.crypto?.subtle) {
    throw new DigestError(
      "This browser exposes no WebCrypto in the current context, so the file cannot be hashed locally.",
    );
  }

  const buffer = await file.arrayBuffer();
  const sha256 = toHex(await crypto.subtle.digest("SHA-256", buffer));

  const header = new Uint8Array(buffer, 0, Math.min(HEADER_SAMPLE_BYTES, buffer.byteLength));

  return {
    name: file.name,
    size: file.size,
    mimeType: file.type,
    sha256,
    headerB64: header.byteLength > 0 ? toBase64(header) : null,
  };
}
