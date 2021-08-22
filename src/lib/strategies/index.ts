import { LocalStorageStrategy } from './localStorage/localStorage';
import { WebAuthnStrategy } from './webAuthn/webAuthn';

export default {
  LocalStorageStrategy: {
    name: 'LocalStorageStrategy',
    strategy: LocalStorageStrategy,
  },
  WebAuthnStrategy: {
    name: 'WebAuthnStrategy',
    strategy: WebAuthnStrategy,
  },
};
