import { Resolver } from 'dns/promises';

import doh from 'dohjs';

import strategies from './strategies';
import { AbstractStrategy } from './strategies/abstract';
import {
  concatTypedArrays,
  decodeBase64,
  encodeBase64,
  hash,
  parseTxtRecordData,
} from './utils';

const DEFAULT_STRATEGY_NAME = 'LocalStorageStrategy';
const DEFAULT_DOH_RESOLVER = 'https://query.hdns.io/dns-query';
const DEFAULT_DNS_RESOLVERS = [
  '103.196.38.38',
  '103.196.38.39',
  '103.196.38.40',
];

export class HandshakeLogin {
  strategy: AbstractStrategy;
  useDoh: boolean;
  resolver;
  dohResolver: doh.DohResolver;

  domain: string;
  idManager: string;
  deviceId: string;
  prefix: string;
  reqData: RequestData;
  resData: ResponseData;
  identity: Identity;

  constructor({
    useDoh = false,
    strategy = new strategies[DEFAULT_STRATEGY_NAME].strategy(),
    dohResolverUrl = DEFAULT_DOH_RESOLVER,
    dnsResolvers = DEFAULT_DNS_RESOLVERS,
  } = {}) {
    this.useDoh = useDoh;
    this.strategy = strategy;

    if (useDoh) {
      this.dohResolver = new doh.DohResolver(dohResolverUrl);
    } else {
      this.resolver = new Resolver();
      const servers = dnsResolvers ?? DEFAULT_DNS_RESOLVERS;
      this.resolver.setServers(servers);
    }
  }

  /**
   * Make DNS Queries
   * @param domain Domain name
   * @param type DNS record type
   * @returns DNS Response Answers array (or null)
   */
  async makeDnsQuery(domain: string, type: string): Promise<DNSRecord[]> {
    if (!domain) throw new Error('Domain not set.');

    if (this.useDoh) {
      const dnsResponse = await this.dohResolver.query(domain, type, 'GET');
      if (!dnsResponse.answers.length) return null;
      return dnsResponse.answers.map((ans) => {
        return {
          name: ans.name,
          type: ans.type,
          value: String.fromCharCode.apply(null, concatTypedArrays(ans.data)),
        };
      });
    } else {
      try {
        const answers = await this.resolver.resolve(domain, type);
        return (answers as string[][]).map((ans) => {
          return { name: domain, type: type, value: ans.join() };
        });
      } catch (error) {
        return null;
      }
    }
  }

  /**
   * Get ID Manager
   * @param domain Domain name
   * @returns url or null
   */
  async getIdManager(): Promise<string> {
    const dnsResponse = await this.makeDnsQuery(
      `_idmanager.${this.domain}`,
      'TXT'
    );
    if (!dnsResponse?.length) return 'https://id.namebase.io';

    const idManagerRecord: IdManagerRecordData = parseTxtRecordData(
      dnsResponse[0].value
    );
    this.idManager = idManagerRecord.url;
    return this.idManager;
  }

  /**
   * Generate Request URL
   * @returns Request URL
   */
  async generateRequestUrl({
    domain,
    challenge,
    callbackUrl,
  }): Promise<string> {
    if (!domain) throw new Error('Domain not set.');
    if (!challenge) throw new Error('Challenge not set.');
    if (!callbackUrl) throw new Error('Callback URL not set.');

    this.domain = domain.toLowerCase();
    const idMgrUrl = await this.getIdManager();
    return `${idMgrUrl}/#/login?state=${encodeBase64(
      challenge
    )}&id=${encodeBase64(this.domain)}&callbackUrl=${encodeBase64(
      callbackUrl
    )}`;
  }

  /**
   * Set Request Data
   * @param reqData Request data to set
   */
  setRequestData(reqData: RequestData) {
    if (!reqData) throw new Error('Request Data not set.');

    this.reqData = reqData;
    this.domain = reqData.domain.toLowerCase();
    this.strategy.setRequestData(this.reqData);
  }

  /**
   * Parse Request Data from URL
   * Uses window.location if url is not passed.
   * @param url url with request data to be parsed
   * @returns request data object
   */
  parseRequestDataFromUrl(url: string = null): RequestData {
    if (!url) {
      url = window.location.href;
    }
    const hash = new URL(url).hash;
    const queryIndex = hash.indexOf('?');
    const regex = /([^&=]+)=([^&]*)/g;
    const queryString = hash.substr(queryIndex + 1);
    const params: Record<string, string> = queryString
      .match(regex)
      .reduce((data, part) => {
        const idx = part.indexOf('=');
        return {
          ...data,
          [part.slice(0, idx)]: decodeBase64(part.slice(idx + 1, part.length)),
        };
      }, {});

    this.setRequestData({
      domain: params.id,
      challenge: params.state,
      callbackUrl: params.callbackUrl,
    });
    return this.reqData;
  }

  /**
   * Get Device Record
   * @returns Device Record Data
   */
  async getDeviceRecord(): Promise<DeviceRecordData> {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.prefix) throw new Error('Prefix not set.');

    const dnsResponse = await this.makeDnsQuery(
      `${this.prefix}._auth.${this.domain}`,
      'TXT'
    );
    if (!dnsResponse?.length) return null;

    const deviceRecord: DeviceRecordData = parseTxtRecordData(
      dnsResponse[0].value
    );

    this.strategy.setDeviceRecord(deviceRecord);
    return deviceRecord;
  }

  /**
   * Generate DNS Record
   * @returns DNS Record
   */
  async generateDnsRecord(): Promise<DNSRecord> {
    return this.strategy.generateDnsRecord(this.prefix);
  }

  /**
   * Verify Fingerprint with DNS
   * @param fingerprint Expected fingerprint
   * @returns boolean if fingerprint is found
   */
  async verifyFingerprintWithDNS(fingerprint: string = null) {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.prefix) throw new Error('Prefix not set.');

    const fingerprintToCompare = fingerprint ?? this.identity.fingerprint;
    const txtData = await this.getDeviceRecord();
    if (!txtData) return false;
    return txtData.fingerprint === fingerprintToCompare;
  }

  /**
   * Use Strategy
   * @param strategy strategy to use
   */
  async useStrategy(strategy: AbstractStrategy) {
    if (!strategy) throw new Error('Strategy not set.');

    this.strategy = strategy;
    if (this.reqData) this.strategy.setRequestData(this.reqData);
    if (this.resData) this.strategy.setResponseData(this.resData);
  }

  /**
   * Get Device ID
   * also calculates prefix
   * @returns device id
   */
  async getDeviceId(): Promise<string> {
    this.deviceId = await this.strategy.getDeviceId();
    await this.getPrefix();
    return this.deviceId;
  }

  /**
   * Generate Identity
   * @returns Identity
   */
  async generateIdentity(): Promise<Identity> {
    this.identity = await this.strategy.generateIdentity();
    return this.identity;
  }

  /**
   * Get existing Identity
   * @returns Identity
   */
  async getIdentity(): Promise<Identity> {
    this.identity = await this.strategy.getIdentity();
    return this.identity;
  }

  /**
   * Get Prefix
   * based on domain and device id
   * @returns prefix
   */
  async getPrefix(): Promise<string> {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.deviceId) throw new Error('Device ID not set.');

    this.prefix = (await hash(this.domain + this.deviceId)).slice(0, 16);
    return this.prefix;
  }

  /**
   * Sign Challenge
   * @returns signature
   */
  async sign(): Promise<string> {
    return this.strategy.sign();
  }

  /**
   * Verify Signature
   * @param challenge
   * @returns boolean whether valid signaure
   */
  async verify(challenge: string) {
    return this.strategy.verify(challenge);
  }

  /**
   * Generate Response Data
   * @returns Response Data
   */
  async generateResponseData(): Promise<ResponseData> {
    if (!this.domain) throw new Error('Domain not set.');
    if (!this.prefix) throw new Error('Prefix not set.');
    if (!this.identity?.publicKey) throw new Error('Public Key not set.');
    if (!this.strategy) throw new Error('Strategy not set.');

    const data: ResponseData = {
      domain: encodeBase64(this.domain), // b64
      deviceId: encodeBase64(this.prefix), // str => b64
      publicKey: encodeBase64(this.identity.publicKey), // str => b64
      strategy: encodeBase64(this.strategy.constructor.name),
      ...(await this.strategy.generateSignatureData()),
    };
    return data;
  }

  /**
   * Generate Response URL
   * @returns response url
   */
  async generateResponseUrl(): Promise<string> {
    if (!this.reqData?.callbackUrl) throw new Error('Callback URL not set.');

    const data = await this.generateResponseData();
    const url = new URL(this.reqData.callbackUrl);
    url.hash = encodeBase64(JSON.stringify(data)); // JSON => str => b64
    return url.toString();
  }

  /**
   * Set Response Data
   * @param resData Response Data
   */
  setResponseData(resData: ResponseData) {
    if (!resData) throw new Error('Response Data not set.');

    this.resData = resData;
    this.domain = resData.domain.toLowerCase();
    this.prefix = resData.prefix ?? resData.deviceId;
    this.strategy.setResponseData(this.resData);
  }

  /**
   * Parse Response Data From URL
   * @param url response url
   * @returns Response Data
   */
  parseResponseDataFromUrl(url = null): ResponseData {
    const hash = new URL(url).hash;
    const b64encoded = hash.slice(1);
    const data: ResponseData = JSON.parse(decodeBase64(b64encoded));

    Object.keys(data).map(function (key) {
      data[key] = decodeBase64(data[key]);
    });
    data.prefix = data.deviceId;
    delete data.deviceId;

    this.setResponseData(data);
    return data;
  }

  /**
   * Verify Response Data
   * Checks signature of challenge and fingerprint with DNS.
   * @param challenge challenge to verify
   * @returns boolean whether valid response
   */
  async verifyResponseData(challenge: string): Promise<boolean> {
    if (!challenge) throw new Error('Challenge not set.');

    const strategy =
      strategies[this.resData.strategy ?? DEFAULT_STRATEGY_NAME] ?? null;
    if (!strategy)
      throw new Error(
        'Strategy not found. You may need to update the library.'
      );
    this.useStrategy(new strategy.strategy());

    const fingerprint = await this.strategy.getFingerprint();
    const fpMatched = await this.verifyFingerprintWithDNS(fingerprint);
    if (!fpMatched) return false;

    return this.strategy.verify(challenge);
  }
}

export const Strategies = strategies;
