import {
  arrayBufferToString,
  Crypto,
  decodeBase64,
  encodeBase64,
  hash,
  stringToArrayBuffer,
  SubtleCrypto,
} from '../../utils';

const identityKeyPrefix = 'handshake:login:identity_';
const ivKeyPrefix = 'handshake:login:iv_';

export async function getIdentity(
  domain: string,
  password?: string
): Promise<Identity> {
  if (!domain) throw new Error('Domain not set.');

  const encryptedIdentity = window.localStorage.getItem(
    `${identityKeyPrefix}${encodeBase64(domain)}`
  );
  if (!encryptedIdentity) return null;

  const iv = stringToArrayBuffer(
    window.localStorage.getItem(`${ivKeyPrefix}${encodeBase64(domain)}`)
  );
  try {
    const identity = await decrypt(
      stringToArrayBuffer(decodeBase64(encryptedIdentity)),
      await getPrivateKey(password),
      iv
    );
    return JSON.parse(arrayBufferToString(identity));
  } catch (error) {
    throw new Error('Invalid password.');
  }
}

export async function saveIdentity(identity: Identity, password?: string) {
  if (!identity) throw new Error('Identity not set.');

  const iv = Crypto.getRandomValues(new Uint8Array(12));
  window.localStorage.setItem(
    `${ivKeyPrefix}${encodeBase64(identity.name)}`,
    arrayBufferToString(iv)
  );
  const encryptedIdentity = await encrypt(
    stringToArrayBuffer(JSON.stringify(identity)),
    await getPrivateKey(password),
    iv
  );

  window.localStorage.setItem(
    `${identityKeyPrefix}${encodeBase64(identity.name)}`,
    encodeBase64(arrayBufferToString(encryptedIdentity))
  );
}

async function getPrivateKey(password?: string) {
  const k = (await hash(await hash(password))).slice(0, 22);
  const privateKey = await SubtleCrypto.importKey(
    'jwk',
    {
      key_ops: ['encrypt', 'decrypt'],
      ext: true,
      kty: 'oct',
      k: k,
      alg: 'A128GCM',
    },
    {
      name: 'AES-GCM',
    },
    false,
    ['encrypt', 'decrypt']
  );
  return privateKey;
}

async function encrypt(
  data: ArrayBuffer,
  privateKey: CryptoKey,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  if (!data) throw new Error('Data to encrypt not set.');
  if (!privateKey) throw new Error('Private Key not set.');
  if (!iv) throw new Error('IV not set.');

  const encryptedData = await SubtleCrypto.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    privateKey,
    data
  );

  return encryptedData;
}

async function decrypt(
  data: ArrayBuffer,
  privateKey: CryptoKey,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  if (!data) throw new Error('Data to decrypt not set.');
  if (!privateKey) throw new Error('Private Key not set.');
  if (!iv) throw new Error('IV not set.');

  const decryptedData = await SubtleCrypto.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    privateKey,
    data
  );
  return decryptedData;
}
