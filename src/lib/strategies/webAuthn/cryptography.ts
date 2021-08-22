import { keyStringToArrayBuffer, SubtleCrypto } from '../../utils';

export function importCryptoKey(pem: string) {
  const binaryDer = keyStringToArrayBuffer(pem);
  return SubtleCrypto.importKey(
    'spki',
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['verify']
  );
}

// https://gist.github.com/philholden/50120652bfe0498958fd5926694ba354
export async function verifySignature(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  data: ArrayBuffer
) {
  const usignature = new Uint8Array(signature);
  const rStart = usignature[4] === 0 ? 5 : 4;
  const rEnd = rStart + 32;
  const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  const r = usignature.slice(rStart, rEnd);
  const s = usignature.slice(sStart);
  const rawSignature = new Uint8Array([...r, ...s]);

  return await SubtleCrypto.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    publicKey,
    rawSignature,
    data
  );
}
