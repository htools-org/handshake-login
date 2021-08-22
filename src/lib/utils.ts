export let Crypto: Crypto;
export let SubtleCrypto: SubtleCrypto;

if (typeof window !== 'undefined' && window.crypto) {
  Crypto = window.crypto;
  SubtleCrypto = Crypto.subtle;
} else {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  Crypto = require('crypto').webcrypto;
  SubtleCrypto = Crypto.subtle;
}

// https://stackoverflow.com/a/62667703/1724828
/**
 * Encode a string of text as base64
 *
 * @param data The string of text.
 * @returns The base64 encoded string.
 */
export function encodeBase64(data: string): string {
  if (typeof btoa === 'function') {
    return btoa(data);
  } else if (typeof Buffer === 'function') {
    return Buffer.from(data, 'utf-8').toString('base64');
  } else {
    throw new Error('Failed to determine the platform specific encoder');
  }
}

/**
 * Decode a string of base64 as text
 *
 * @param data The string of base64 encoded text
 * @returns The decoded text.
 */
export function decodeBase64(data: string): string {
  if (typeof atob === 'function') {
    return atob(data);
  } else if (typeof Buffer === 'function') {
    return Buffer.from(data, 'base64').toString('utf-8');
  } else {
    throw new Error('Failed to determine the platform specific decoder');
  }
}

export function parseTxtRecordData(str: string): Record<string, string> {
  if (str.startsWith('"')) str = str.slice(1);
  if (str.endsWith('"')) str = str.slice(0, -1);
  const txtDataObj = str.split(';').reduce((data, part) => {
    const tmp = part.split('=');
    return { ...data, [tmp[0]]: tmp[1] };
  }, {});
  return txtDataObj;
}

export function concatTypedArrays(arrays: Uint8Array[]): Uint8Array {
  let length = 0;
  arrays.forEach((item) => {
    length += item.length;
  });
  // Create a new array with total length and merge all source arrays.
  const mergedArray = new Uint8Array(length);
  let offset = 0;
  arrays.forEach((item) => {
    mergedArray.set(item, offset);
    offset += item.length;
  });
  // Should print an array with length 90788 (5x 16384 + 8868 your source arrays)
  return mergedArray;
}

export async function hash(text: string): Promise<string> {
  const textEncoder = new TextEncoder();
  const fingerprint = await SubtleCrypto.digest(
    'SHA-256',
    textEncoder.encode(encodeBase64(text))
  );
  const hashArray = Array.from(new Uint8Array(fingerprint));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''); // convert bytes to hex string
  return hashHex;
}

export function stringToArrayBuffer(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
export function arrayBufferToString(buf: ArrayBuffer): string {
  return String.fromCharCode.apply(null, Array.from(new Uint8Array(buf)));
}

const textEncoder = new TextEncoder();
export function encodeText(str: string): Uint8Array {
  return textEncoder.encode(str);
}

export async function exportCryptoKey(key: CryptoKey): Promise<string> {
  const exported = await SubtleCrypto.exportKey('spki', key);
  const exportedAsString = arrayBufferToString(exported);
  const exportedAsBase64 = encodeBase64(exportedAsString);
  return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
}

export async function calculateFingerprint(key: CryptoKey): Promise<string> {
  const exported = await SubtleCrypto.exportKey('spki', key);
  const fingerprint = await SubtleCrypto.digest('SHA-256', exported);
  const hashArray = Array.from(new Uint8Array(fingerprint));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''); // convert bytes to hex string
  return hashHex;
}

export async function exportPrivateCryptoKey(key: CryptoKey): Promise<string> {
  const exported = await SubtleCrypto.exportKey('pkcs8', key);
  const exportedAsString = arrayBufferToString(exported);
  const exportedAsBase64 = encodeBase64(exportedAsString);
  return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
}

export function keyStringToArrayBuffer(pem: string): ArrayBuffer {
  const cleanKey = pem
    .replace(/\n?-{5}\n?[\w\s]+\n?-{5}\n?/g, '')
    .replace(/=+$/g, '');

  // base64 decode the string to get the binary data
  const binaryDerString = decodeBase64(cleanKey);
  // convert from a binary string to an ArrayBuffer
  return stringToArrayBuffer(binaryDerString);
}
