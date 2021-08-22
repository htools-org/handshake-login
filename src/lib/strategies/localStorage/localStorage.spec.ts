import { expect } from 'chai';

import { decodeBase64 } from '../../utils';

import { LocalStorageStrategy } from './localStorage';

describe('Strategy - Local Storage', function () {
  const localStorageStrategy = new LocalStorageStrategy();

  before(function () {
    localStorageStrategy.setRequestData({
      domain: 'example',
      challenge: '7mhD9Lx_i_lEg98S7DYVC19bQswvpK_ywaVBng2uy0U',
      callbackUrl: 'https://localhost/callback',
    });
  });

  it('Creates and Gets Device ID', async function () {
    const deviceId = await localStorageStrategy.getDeviceId();
    expect(deviceId).to.be.a.string;

    const deviceIdAgain = await localStorageStrategy.getDeviceId();
    expect(deviceIdAgain).to.equal(deviceId);
  });

  it('Generates and saves an Identity', async function () {
    const identity = await localStorageStrategy.generateIdentity();
    expect(identity).to.have.all.keys([
      'name',
      'publicKey',
      'privateKey',
      'fingerprint',
    ]);

    const identityAgain = await localStorageStrategy.getIdentity();
    expect(identityAgain).to.deep.equal(identity);

    const identityAgain2 = await localStorageStrategy.getIdentity();
    expect(identityAgain2).to.deep.equal(identity);
  });

  it('Signs challenge and verifies signature', async function () {
    const signature = await localStorageStrategy.sign();
    expect(signature).to.be.a.string;

    // challenge needs to be specified as reqData will not be available on callback
    // (and should not be taken from resData)
    const challenge = localStorageStrategy.reqData.challenge;

    localStorageStrategy.setResponseData({
      domain: 'example',
      deviceId: 'prefix',
      publicKey: localStorageStrategy.identity.publicKey,
      signed: decodeBase64(signature),
    });

    const verified = await localStorageStrategy.verify(challenge);
    expect(verified).to.be.true;
  });
});
