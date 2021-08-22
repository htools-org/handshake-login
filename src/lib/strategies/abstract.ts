/**
 * Abstract Strategy
 * An abstract class that other strategies inherit
 */
export abstract class AbstractStrategy {
  abstract domain: string;
  abstract identity: Identity;

  abstract reset();
  abstract setRequestData(reqData: RequestData);
  abstract setDeviceRecord(deviceRecord: DeviceRecordData);
  abstract setResponseData(resData: ResponseData);
  abstract getDeviceId(): Promise<string>;
  abstract generateIdentity(): Promise<Identity>;
  abstract getIdentity(): Promise<Identity>;
  abstract sign(): Promise<string>;
  abstract verify(challenge: string): Promise<boolean>;
  abstract generateDnsRecord(prefix: string): Promise<DNSRecord>;
  abstract generateSignatureData(): Promise<Record<string, string>>;
  abstract getFingerprint(): Promise<string>;
}
