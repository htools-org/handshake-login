interface RequestData {
  domain: string;
  challenge: string;
  callbackUrl: string;
}

interface ResponseData {
  domain: string;
  deviceId: string; // actually the prefix
  publicKey: string;
  signed?: string; // signature
  strategy?: string;
  prefix?: string;
  [x: string]: string;
}

interface DNSRecord {
  type: string;
  name: string;
  value: string;
}

interface DeviceRecordData {
  v?: string;
  fingerprint?: string;
  // pubKey?: string;
  [x: string]: string;
}

interface IdManagerRecordData {
  v?: string;
  url?: string;
  [x: string]: string;
}

interface Identity {
  name: string;
  publicKey: string;
  fingerprint: string;
  privateKey?: string;
  keyId?: string;
}
