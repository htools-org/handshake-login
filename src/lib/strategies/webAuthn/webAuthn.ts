/* eslint-disable @typescript-eslint/ban-ts-comment */

import {
  arrayBufferToString,
  calculateFingerprint,
  decodeBase64,
  encodeBase64,
  exportCryptoKey,
  hash,
  stringToArrayBuffer,
  SubtleCrypto,
} from '../../utils';
import { AbstractStrategy } from '../abstract';

import { importCryptoKey, verifySignature } from './cryptography';

/**
 * WebAuthn Strategy
 */
export class WebAuthnStrategy extends AbstractStrategy {
  readonly strategyName = 'WebAuthnStrategy';
  domain: string;
  identity: Identity;
  reqData: RequestData;
  resData: ResponseData;
  deviceRecord: DeviceRecordData;
  signature;
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;

  constructor() {
    super();
  }

  /**
   * Reset all properties
   */
  reset() {
    this.domain = null;
    this.identity = null;
    this.signature = null;
    this.clientDataJSON = null;
    this.authenticatorData = null;
    this.reqData = null;
    this.resData = null;
    this.deviceRecord = null;
  }

  /**
   * Set Request Data
   * @param reqData Request data to set
   */
  setRequestData(reqData: RequestData) {
    this.reset();
    this.reqData = reqData;
    this.domain = reqData.domain.toLowerCase();
  }

  /**
   * Set Device Record
   * @param deviceRecord Device record to set
   */
  setDeviceRecord(deviceRecord: DeviceRecordData) {
    this.deviceRecord = deviceRecord;
  }

  /**
   * Set Response Data
   * @param resData Response data to set
   */
  setResponseData(resData: ResponseData) {
    this.resData = resData;
    this.domain = resData.domain;
  }

  /**
   * Get Device ID
   * @returns device id
   */
  async getDeviceId(): Promise<string> {
    return window.location.hostname;
  }

  /**
   * Create Challenge from Request Data
   * @returns challenge as Uint8Array
   */
  _createChallenge(): Uint8Array {
    if (!this.reqData.challenge) throw new Error('Challenge not set.');

    const challenge = stringToArrayBuffer(this.reqData.challenge);
    return new Uint8Array(challenge);
  }

  /**
   * Generate new Identity
   * @returns Identity
   */
  async generateIdentity(): Promise<Identity> {
    if (!this.domain) throw new Error('Domain not set.');

    const challenge = this._createChallenge();

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array(challenge),
        rp: { name: 'Handshake Login', id: window.location.hostname },
        user: {
          id: new Uint8Array([79]),
          name: this.domain,
          displayName: this.domain,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 60000,
        attestation: 'direct',
      },
    });

    // @ts-ignore
    const publicKeyAb = credential.response.getPublicKey();
    const publicKey = await SubtleCrypto.importKey(
      'spki',
      publicKeyAb,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    );
    const publicKeyPem = await exportCryptoKey(publicKey);

    const identity: Identity = {
      name: this.domain,
      // @ts-ignore
      keyId: encodeBase64(arrayBufferToString(credential.rawId)).replace(
        /=+$/,
        ''
      ),
      publicKey: publicKeyPem,
      fingerprint: await hash(publicKeyPem),
    };
    this.identity = identity;
    return identity;
  }

  /**
   * Get an Identity
   * @param domain domain name
   * @returns Identity object
   */
  async getIdentity(): Promise<Identity> {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.deviceRecord) return null;
    if (!this.deviceRecord?.keyId) throw new Error('Key ID not set.');

    const challenge = this._createChallenge();

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        rpId: window.location.hostname,
        allowCredentials: [
          {
            type: 'public-key',
            id: stringToArrayBuffer(decodeBase64(this.deviceRecord.keyId)),
          },
        ],
        userVerification: 'discouraged',
      },
    });

    let publicKey;
    try {
      publicKey = await SubtleCrypto.importKey(
        'spki',
        stringToArrayBuffer(decodeBase64(this.deviceRecord.pubKey)),
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        []
      );
    } catch (error) {
      console.error(error);
      throw new Error('Could not import invalid public key.');
    }

    const publicKeyPem = await exportCryptoKey(publicKey);

    const identity: Identity = {
      name: this.domain,
      keyId: this.deviceRecord.keyId,
      publicKey: publicKeyPem,
      fingerprint: await hash(publicKeyPem),
    };
    this.identity = identity;

    // @ts-ignore
    this.signature = credential.response.signature;
    // @ts-ignore
    this.authenticatorData = credential.response.authenticatorData;
    // @ts-ignore
    this.clientDataJSON = credential.response.clientDataJSON;
    return identity;
  }

  /**
   * Sign challenge
   * @returns signed data
   */
  async sign() {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.reqData.challenge) throw new Error('Challenge not set.');

    return encodeBase64(this.signature);
  }

  /**
   * Verify signature
   * @param challenge challenge to verify signature with
   * @returns boolean if signature verified
   */
  async verify(challenge: string) {
    if (!challenge) throw new Error('Challenge not set.');
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.resData) throw new Error('Response Data not set.');

    const clientDataJSON = stringToArrayBuffer(this.resData.clientDataJSON);
    const authenticatorData = stringToArrayBuffer(
      this.resData.authenticatorData
    );

    const clientData = JSON.parse(this.resData.clientDataJSON);
    if (encodeBase64(challenge).replace(/=+$/, '') !== clientData.challenge) {
      return false;
    }

    const clientDataJSONHash = await SubtleCrypto.digest(
      'SHA-256',
      clientDataJSON
    );

    const verifiableData = new Uint8Array(
      authenticatorData.byteLength + clientDataJSONHash.byteLength
    );
    verifiableData.set(new Uint8Array(authenticatorData), 0);
    verifiableData.set(
      new Uint8Array(clientDataJSONHash),
      authenticatorData.byteLength
    );

    const publicKeyObj = await importCryptoKey(this.resData.publicKey);

    const signatureVerified = await verifySignature(
      publicKeyObj,
      stringToArrayBuffer(this.resData.signed),
      verifiableData
    );
    return signatureVerified;
  }

  /**
   * Generate DNS Record for Identity
   * @param prefix derived from domain and device id
   * @returns DNSRecord
   */
  async generateDnsRecord(prefix: string): Promise<DNSRecord> {
    if (!prefix) throw new Error('Prefix not set.');
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.identity?.publicKey) throw new Error('Public Key not set.');
    if (!this.identity?.fingerprint) throw new Error('Fingerprint not set.');
    if (!this.identity?.keyId) throw new Error('Key ID not set.');

    const cleanPublicKey = this.identity.publicKey
      .replace(/\n?-{5}\n?[\w\s]+\n?-{5}\n?/g, '')
      .replace(/=+$/g, '');
    return {
      type: 'TXT',
      name: `${prefix}._auth.${this.domain}.`,
      value: `v=0;fingerprint=${this.identity.fingerprint};keyId=${this.identity.keyId};pubKey=${cleanPublicKey}`,
    };
  }

  /**
   * Generate Signature Data
   * @returns partial response data
   */
  async generateSignatureData(): Promise<Record<string, string>> {
    if (!this.signature) throw new Error('Signature not set.');
    if (!this.clientDataJSON) throw new Error('ClientDataJSON not set.');
    if (!this.authenticatorData) throw new Error('AuthenticatorData not set.');

    return {
      signed: encodeBase64(arrayBufferToString(this.signature)),
      clientDataJSON: encodeBase64(arrayBufferToString(this.clientDataJSON)),
      authenticatorData: encodeBase64(
        arrayBufferToString(this.authenticatorData)
      ),
    };
  }

  /**
   * Get Fingerprint from Response Data's Public Key
   * @returns fingerprint
   */
  async getFingerprint(): Promise<string> {
    if (!this.resData?.publicKey) throw new Error('Public Key not set.');

    let pubKey: CryptoKey;
    try {
      pubKey = await importCryptoKey(this.resData.publicKey);
    } catch (error) {
      console.error(error);
      throw new Error('Could not import invalid public key.');
    }
    return calculateFingerprint(pubKey);
  }
}
