// https://github.com/namebasehq/handshake-id-manager/blob/master/src/services/DeviceService/index.ts

import {
  calculateFingerprint,
  encodeBase64,
  exportCryptoKey,
  exportPrivateCryptoKey,
  hash,
} from '../../utils';
import { AbstractStrategy } from '../abstract';

import * as cryptography from './cryptography';
import * as store from './store';

/**
 * Local Storage Strategy
 */
export class LocalStorageStrategy extends AbstractStrategy {
  readonly strategyName = 'LocalStorageStrategy';
  storageKey: string;
  reqData: RequestData;
  resData: ResponseData;
  domain: string;
  deviceRecord: DeviceRecordData;
  identity: Identity;
  strategyOptions: Record<string, unknown>;

  constructor() {
    super();
    this.storageKey = 'handshake:login:deviceId';
  }

  /**
   * Reset all properties
   */
  reset() {
    this.domain = null;
    this.identity = null;
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
   * and generate if it doesn't exist
   * @returns device id
   */
  async getDeviceId(): Promise<string> {
    return (
      window.localStorage.getItem(this.storageKey) ??
      this._generateNewDeviceId()
    );
  }

  /**
   * Generate and store new Device ID
   * @returns new device id
   * @private
   */
  _generateNewDeviceId(): string {
    const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0,
          v = c == 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }
    );
    window.localStorage.setItem(this.storageKey, uuid);
    return uuid;
  }

  /**
   * Generate new Identity
   * @returns Identity
   */
  async generateIdentity(): Promise<Identity> {
    if (!this.domain) throw new Error('Domain not set.');

    const { privateKey, publicKey } = await cryptography.generateKeyPair();
    const publicKeyString = await exportCryptoKey(publicKey);
    const identity: Identity = {
      name: this.domain,
      publicKey: publicKeyString,
      privateKey: await exportPrivateCryptoKey(privateKey),
      fingerprint: await hash(publicKeyString),
    };
    await store.saveIdentity(
      identity,
      this.strategyOptions?.password as string
    );
    this.identity = identity;
    return identity;
  }

  /**
   * Get an Identity
   * @returns Identity
   */
  async getIdentity(): Promise<Identity> {
    if (!this.domain) throw new Error('Domain not set.');

    this.identity = await store.getIdentity(
      this.domain,
      this.strategyOptions?.password as string
    );
    return this.identity;
  }

  /**
   * Sign challenge
   * @returns signed data
   */
  async sign(): Promise<string> {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.reqData?.challenge) throw new Error('Challenge not set.');
    if (!this.identity?.privateKey) throw new Error('Private Key not set.');

    let privateKey: CryptoKey;
    try {
      privateKey = await cryptography.importCryptoPrivateKey(
        this.identity.privateKey
      );
    } catch (error) {
      console.error(error);
      throw new Error('Could not import invalid private key.');
    }
    const signature = await cryptography.sign(
      privateKey,
      this.reqData.challenge
    );
    return encodeBase64(signature);
  }

  /**
   * Verify signature
   * @param challenge challenge to verify signature with
   * @returns boolean if signature verified
   */
  async verify(challenge: string): Promise<boolean> {
    if (!challenge) throw new Error('Challenge not set.');
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.resData?.publicKey) throw new Error('Public Key not set.');
    if (!this.resData?.signed) throw new Error('Signature not set.');

    let publicKey: CryptoKey;
    try {
      publicKey = await cryptography.importCryptoKey(this.resData.publicKey);
    } catch (error) {
      console.error(error);
      throw new Error('Could not import invalid public key.');
    }
    const signatureVerified = await cryptography.verifySignature(
      publicKey,
      this.resData.signed,
      challenge
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
    if (!this.identity?.fingerprint) throw new Error('Fingerprint not set.');

    return {
      type: 'TXT',
      name: `${prefix}._auth.${this.domain}.`,
      value: `v=0;fingerprint=${this.identity.fingerprint}`,
    };
  }

  /**
   * Generate Signature Data
   * @returns partial response data
   */
  async generateSignatureData(): Promise<Record<string, string>> {
    return {
      signed: await this.sign(), // Buffer => b64 => b64 (https://github.com/namebasehq/handshake-id-manager/issues/6)
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
      pubKey = await cryptography.importCryptoKey(this.resData.publicKey);
    } catch (error) {
      console.error(error);
      throw new Error('Could not import invalid public key.');
    }
    return calculateFingerprint(pubKey);
  }
}
