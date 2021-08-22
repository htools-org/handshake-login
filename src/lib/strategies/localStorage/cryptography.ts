import {
  arrayBufferToString,
  decodeBase64,
  encodeBase64,
  encodeText,
  keyStringToArrayBuffer,
  stringToArrayBuffer,
  SubtleCrypto,
} from '../../utils';

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return SubtleCrypto.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 4096,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-512',
    },
    true,
    ['sign', 'verify']
  );
}

export function importCryptoKey(pem: string) {
  const binaryDer = keyStringToArrayBuffer(pem);
  return SubtleCrypto.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSA-PSS',
      hash: 'SHA-512',
    },
    true,
    ['verify']
  );
}

export function importCryptoPrivateKey(pem: string) {
  const binaryDer = keyStringToArrayBuffer(pem);
  return SubtleCrypto.importKey(
    'pkcs8',
    binaryDer,
    {
      name: 'RSA-PSS',
      hash: 'SHA-512',
    },
    true,
    ['sign']
  );
}

export async function sign(privateKey: CryptoKey, data: string) {
  const signature = await SubtleCrypto.sign(
    {
      name: 'RSA-PSS',
      saltLength: 64,
    },
    privateKey,
    encodeText(data)
  );
  const exportedAsString = arrayBufferToString(signature);
  const exportedAsBase64 = encodeBase64(exportedAsString);
  return exportedAsBase64;
}

export async function verifySignature(
  publicKey: CryptoKey,
  signature: string,
  data: string
) {
  const binaryDerString = decodeBase64(signature);
  const binaryDer = stringToArrayBuffer(binaryDerString);
  return await SubtleCrypto.verify(
    {
      name: 'RSA-PSS',
      saltLength: 64,
    },
    publicKey,
    binaryDer,
    encodeText(data)
  );
}
