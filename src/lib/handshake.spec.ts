import { expect } from 'chai';

import { HandshakeLogin, Strategies } from './handshake';

// Example constants for tests
const SAMPLE_ID_MGR_REQ_URL =
  'https://id.htools.work/#/login?state=YWJjZGU=&id=ZXhhbXBsZQ==&callbackUrl=aHR0cHM6Ly9sb2NhbGhvc3QvY2FsbGJhY2s=';
const SAMPLE_RESPONSE_URL =
  'https://localhost/callback#eyJkb21haW4iOiJaWGhoYlhCc1pRPT0iLCJkZXZpY2VJZCI6Ik9UWmtZalkyTjJGaU1qQmlOR1l3TUE9PSIsInB1YmxpY0tleSI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVbEpRMGxxUVU1Q1oydHhhR3RwUnpsM01FSkJVVVZHUVVGUFEwRm5PRUZOU1VsRFEyZExRMEZuUlVGMVpsWllPVWR4YnpOWlkxQm1ZbGRPVEdsRmNuQkRVbTFsVTNJNWNpdGFNRnBUWld0WmEwSktZbHBzU0dKQmFrOWlTM0IwYjFBeFUzZGlhalIwZDJSd2VVSnlWM2g0VFdSV0syZFpRMGRsTVdoTVZEbERMMllyU21SNmVtazRjbEZaU2pndk5reEJMMUZQZUc1SGRVdG5WekZqWW01WFlUTkRWVXMyYUdoc1ptNWthek5oZUdSbE4wMTZUVWhQYlVsQlNISlJRMmxMYmtVek5VaDBWRnBHWlVGeFFWWnpNVFo1VkZvMWJGZG1ZbVp2YUhOUlNYRnFjMVZVU2pKaU1HeDVhbkl2UzNkWk1FbzBla1JzUXpkYU1VMTNLM1ZtUXpaR2JUWkhkRmRyWm5nM2FHbzRSV3AwYVZCS05tWjJlVU5JYTJ4YU1tVjJNbTlsYlZwNmIwdHpSMEp1YVRCeU1uWnJWVXM1V201TWJYVjBLME5CVVhVME9GTXJPRnBVY0VvdlZ5OVlaWFZ0UTNoVVRXOVdSR05tTjFBeEszbDVWRmNyVW1wM1RXSTVaV2xHVjNCTlRHVTRZelpTVG5WcWFHa3dlUzl0V214dllrUmhOVWQzV0V4SFJXTTRTVGsyVnpsaFJXUktXVFpLVFRKQ09WVjZiWEpvWlhsdVZrNXZRVE5wVlRKSVNWaGxabFZrY21WelZrb3JTamx5WlZGWWNteHRXblIzWm1Sb2VrRmxMM1pGZHpGaFFUaHNXVzByZUhZNVVGUnBibTFTVmpneldHeEhaWFZqT0Zka2JXaHNVM0Z0ZVdsUWVYSnlLMkpZTUhSeGRXcFZUVVZ3Ym5WNlJEZHVXa3h3WkVrNU1rWXliVnBHWldadFFUWlJjbk5zU0ZwcFRUSklZbXA1Y0VoT0swbHBVbTFLUkROaGNsRjBaSE00UmpKeFJqbFViblZhYVRCR1FUaElNMUZuYlZjMFFXOTZRWFpPUldsSWNFRkxjRU52UldsRWRVVXpXWGN2UW1obGIzaE5hVU4zVmk5SU5tcGhSRTR4Y25OUFJXMHZRbXQyYkVSaFFtNU9URXRZVGpSSlQwTnJjV3BZVlZGb2VsVjVSRlJxV2tjelRIYzVOVk50UVN0bFJ6TlhVbTE1VGs5MVluWnhSbnA1VkhFeU1HUTFiM05wU0dWaVJuVTBOR1F6Tm1aak0ycFZWa1pGT0VOQmQwVkJRVkU5UFFvdExTMHRMVVZPUkNCUVZVSk1TVU1nUzBWWkxTMHRMUzA9Iiwic3RyYXRlZ3kiOiJURzlqWVd4VGRHOXlZV2RsVTNSeVlYUmxaM2s9Iiwic2lnbmVkIjoiVG5aTlFVRkRNMFZLYzNsMFEwdHROSFZETjNkbVIybDBhR3h5WmpoUGNHUTVTMUpNYlVOTU1IbzJZVGRXVTI5TE9GTXZTalpMWm1KbUt6bHFkMlJaYWxkdU1EUTVkVkEzWW5CbmQwbG1XVVJDTlM5eVluaDJSMDh6V1hKMlkwVm5RVU01UkRsS05rUm5hR2xUYWtWM1RXNDNabTkwVFhCQlQydzVRMXBLV21aRk1FTTFOME0yV0c5VlNtWlNVRGcyYkZkT1dXbGtUbkUwYlZOM1IxcHRXRUpJTlVWalRYTXJSMWxvTjFoSVEzUjRjMWwwTlVkc1ZHWnlWVWhLZW1rMGIwNUJlbU5VTkRCb01YQjVVa1pUUnprelN6RkJha2hWTm5KTVl6TlFkRVpyUm0xeGNGWlFLelV3U0RSQ1JHOU1XblF2Ym1nNFJHUm9NWEJhWWpGUk1GWlhjRkl4TUROcFRGRXJVamRRYWxJMEsyUklUMUV2TWtvNFMzcFhVSGRzWTJGSWFrMHdibGw0TkhWTFdVMUhUemcwV1dSemVtOTZhR2swY2tkNlpGVlNlazAxT0hBdlpHeHNkRUpVV25KdVZtNVFNVWhvYkRCU0x6UnhOMnBWU1VObVZrNUNZekYwUkdONlNVSXdMMjVTUW00M1dVVTRiWGxXTml0cWIxcHJXRmhqYzNaRlpITkpNVzlwYzJWSE5Tc3ZaVzVSSzA1WlJHSmhVRU4yZEd0WFRVaHJlVkpEZVc1VlVWVlJRVVJsZVZGMlpXRXJSVGhJVUVwR2FubzVTRVpXWWxoRlowZHNlRmd5TXpJMWRtWmFiMEV6Y1VjMmJIZEJNVE5JU2tGS2Qxb3pPVXR3U1ZndmJWQkxUME5rTDJoaFZtdGpWbkEzUlhoNFMyeHFXalIyTDJrNVJYWkhUSGhwU25JMmFsRlBOMUp5U2tveVNsWnpkMDAzYlhaS2VuZGphRlJxYlN0VE1EVmtVV1V6WkRSWFZ6Wk9UWHBNVWxScVRDOTNPWGR5WVhvMFpTOUdVVVpWY0N0SllUTnZhbFZPVERSVU1FUTRaalJ1SzJsUWVHUXZVMHRxVkdGclNXWlZjU3RqVTBzME9XUkRlRkJCTVZwelNXdElVbmwzU0VSVmVIUnRkRWhVTjNwSEx6aHpTbUl2Wnl0eGFrNU5abm8yT0dwUFVFcGliMmR2TVdkbVIzSlFSa1U5In0=';
const SAMPLE_DOMAIN = 'example';
const SAMPLE_CHALLENGE = 'abcde';
const SAMPLE_CALLBACK_URL = 'https://localhost/callback';
const SAMPLE_GOOD_PREFIX = '96db667ab20b4f00';
const SAMPLE_BAD_PREFIX = 'badprefix';
const SAMPLE_GOOD_FINGERPRINT =
  '9f22098557aacc83fd3d7d2f4bf203d4b1fd3006d7dcf26adec1f186f48efc14';
const SAMPLE_BAD_FINGERPRINT = 'badfingerprint';

describe('Handshake Login', function () {
  const hLogin = new HandshakeLogin();

  hLogin.makeDnsQuery = async function (
    domain: string,
    type = 'TXT'
  ): Promise<DNSRecord[]> {
    return {
      TXT: {
        '_idmanager.example': [
          {
            name: domain,
            type: 'TXT',
            value: 'v=0;url=https://id.htools.work',
          },
        ],
        '96db667ab20b4f00._auth.example': [
          {
            name: domain,
            type: 'TXT',
            value:
              'v=0;fingerprint=9f22098557aacc83fd3d7d2f4bf203d4b1fd3006d7dcf26adec1f186f48efc14',
          },
        ],
        'badprefix._auth.example': null,
      },
    }[type][domain];
  };

  it('Makes DNS queries', async function () {
    // DNS
    const hLoginWithDNS = new HandshakeLogin();
    const dnsResponse = await hLoginWithDNS.makeDnsQuery('rithvik', 'TXT');
    expect(dnsResponse).to.be.an('array').that.is.not.empty;

    // DOH
    const hLoginWithDOH = new HandshakeLogin({ useDoh: true });
    const dohResponse = await hLoginWithDOH.makeDnsQuery('rithvik', 'TXT');
    expect(dohResponse).to.be.an('array').that.is.not.empty;

    // Negative tests
    expect(async () => await hLoginWithDOH.makeDnsQuery(null, null)).to.throw;
  });

  it('Gets ID Manager', async function () {
    // Explicit ID Manager is not set
    hLogin.setRequestData({
      domain: 'noid.' + SAMPLE_DOMAIN,
      challenge: SAMPLE_CHALLENGE,
      callbackUrl: SAMPLE_CALLBACK_URL,
    });
    expect(await hLogin.getIdManager()).to.equal('https://id.namebase.io');

    // Explicit ID Manager is set
    hLogin.setRequestData({
      domain: SAMPLE_DOMAIN,
      challenge: SAMPLE_CHALLENGE,
      callbackUrl: SAMPLE_CALLBACK_URL,
    });
    expect(await hLogin.getIdManager()).to.be.a.string;
  });

  it('Generates Request URL', async function () {
    const reqUrl = await hLogin.generateRequestUrl({
      domain: SAMPLE_DOMAIN,
      challenge: SAMPLE_CHALLENGE,
      callbackUrl: SAMPLE_CALLBACK_URL,
    });
    expect(reqUrl).to.equal(SAMPLE_ID_MGR_REQ_URL);
  });

  it('Parses Request Data from URL', async function () {
    const url = SAMPLE_ID_MGR_REQ_URL;
    const reqData = hLogin.parseRequestDataFromUrl(url);

    expect(reqData).to.deep.equal({
      domain: SAMPLE_DOMAIN,
      challenge: SAMPLE_CHALLENGE,
      callbackUrl: SAMPLE_CALLBACK_URL,
    });
  });

  it('Checks if device is registered', async function () {
    hLogin.domain = SAMPLE_DOMAIN;

    hLogin.prefix = SAMPLE_GOOD_PREFIX;
    const goodDeviceRecord = await hLogin.getDeviceRecord();
    expect(goodDeviceRecord).to.have.keys(['v', 'fingerprint']);

    hLogin.prefix = SAMPLE_BAD_PREFIX;
    const nxDeviceRecord = await hLogin.getDeviceRecord();
    expect(nxDeviceRecord).to.be.null;
  });

  it('Formats DNS TXT Record to add', async function () {
    hLogin.domain = SAMPLE_DOMAIN;
    hLogin.prefix = SAMPLE_GOOD_PREFIX;
    hLogin.strategy.domain = SAMPLE_DOMAIN;
    hLogin.strategy.identity = {
      fingerprint: SAMPLE_GOOD_FINGERPRINT,
      name: null,
      publicKey: null,
      privateKey: null,
    };
    const dnsRecord = await hLogin.generateDnsRecord();
    expect(dnsRecord).to.have.keys(['type', 'name', 'value']);
  });

  it('Verifies fingerprint with DNS', async function () {
    hLogin.domain = SAMPLE_DOMAIN;

    hLogin.prefix = SAMPLE_GOOD_PREFIX;
    const goodFingerprintVerified = await hLogin.verifyFingerprintWithDNS(
      SAMPLE_GOOD_FINGERPRINT
    );
    expect(goodFingerprintVerified).to.be.true;

    hLogin.prefix = SAMPLE_GOOD_PREFIX;
    const badFingerprintVerified = await hLogin.verifyFingerprintWithDNS(
      SAMPLE_BAD_FINGERPRINT
    );
    expect(badFingerprintVerified).to.be.false;
  });

  it('Selects a Strategy', async function () {
    hLogin.useStrategy(new Strategies.LocalStorageStrategy.strategy());
    expect(hLogin.strategy).to.be.an.instanceOf(
      Strategies.LocalStorageStrategy.strategy
    );
  });

  it('Generates Response URL', async function () {
    hLogin.setRequestData({
      domain: SAMPLE_DOMAIN,
      challenge: SAMPLE_CHALLENGE,
      callbackUrl: SAMPLE_CALLBACK_URL,
    });
    await hLogin.getDeviceId();
    (await hLogin.getIdentity()) || (await hLogin.generateIdentity());
    const responseUrl = await hLogin.generateResponseUrl();
    expect(responseUrl).to.be.a.string;
  });

  it('Parses Response Data from URL', async function () {
    const responseData = hLogin.parseResponseDataFromUrl(SAMPLE_RESPONSE_URL);
    expect(responseData).to.include.all.keys([
      'domain',
      'prefix',
      'publicKey',
      'signed',
    ]);
  });

  it('Verifies Response Signature', async function () {
    hLogin.parseResponseDataFromUrl(SAMPLE_RESPONSE_URL);
    const challenge = SAMPLE_CHALLENGE;
    const verified = await hLogin.verifyResponseData(challenge);
    expect(verified).to.be.true;
  });
});
