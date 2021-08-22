# Handshake Login

[![npm](https://img.shields.io/npm/v/handshake-login)](https://www.npmjs.com/package/handshake-login) [![License](https://img.shields.io/npm/l/handshake-login)](https://github.com/rithvikvibhu/handshake-login/blob/master/LICENSE) [![Codecov](https://img.shields.io/codecov/c/github/rithvikvibhu/handshake-login)]() [![GitHub issues](https://img.shields.io/github/issues/rithvikvibhu/handshake-login)](https://github.com/rithvikvibhu/handshake-login/issues)

A (fully-typed) JavaScript library for authentication with Handshake names, for use by validating servers (websites) and identity managers.

## Features

- Add **Login with Handshake** to your website
- Build Identity Managers
- Use without any intermediaries (OAuth servers, etc.)
- Works in NodeJs and Browsers
- Supports multiple strategies

## Demo

This library is used in an example Express server ([repo](https://github.com/rithvikvibhu/sample-hs-login-server)).
Try it out at https://sample-hs-login-server.herokuapp.com/.

It is also used in an [identity manager](https://github.com/rithvikvibhu/modular-id-manager).

## Installation

**NodeJs:** Requires NodeJs v16+ if used on the server-side as it depends on native SubtleCrypto.
**Browsers:** The v16+ requirement doesn't apply if it is used in a browser context (so a React/Vue app being developed with NodeJs v14 is fine.)

Install it with:

```sh
npm install --save handshake-login
# or
yarn add handshake-login
```

## Usage/Examples

### Websites

To add Login With Handshake to your website, only 2 main methods are needed: one to generate a request URL and another to verify the response on callback.

```javascript
const hLogin = new HandshakeLogin();
const requestUrl = await hLogin.generateRequestUrl({
  domain: 'example',
  challenge: 'randomly-generated-challenge-keep--track-server-side',
  callbackUrl: 'http://localhost:3000/callback',
});
// Redirect to requestUrl

// On Callback
const hLogin = new HandshakeLogin();
const responseData = hLogin.parseResponseDataFromUrl(url);
const verified = await hLogin.verifyResponseData(req.session.challenge);
// Authenticate based on `verified` boolean
// That's it!
```

Check out this [example Express server](https://github.com/rithvikvibhu/sample-hs-login-server) for a compelete example.

### Identity Managers / Other Use Cases

Documentation is generated and explains all public methods.
Check out this [identity manager](https://github.com/rithvikvibhu/modular-id-manager) for how the different methods can be used.

## Documentation

Generated documentation (with TypeDoc) is available at TODO.

## Running Tests

To run tests, run the following command:

```sh
npm run test
```

Code coverage reports can be generated with:

```sh
npm run cov
```

## Contributing

Contributions are always welcome! However, please create an issue before starting any work so there won't be any repeated/wasted effort.

To add new strategies, have a look at `lib/strategies/`. Similar to existing ones, create a new folder and make the class inherit the `AbstractStrategy` class.

## Development

Clone the project

```sh
git clone git@github.com:rithvikvibhu/handshake-login.git
cd handshake-login
```

Install dependencies

```sh
npm install
```

In 2 terminals, start the build and test watchers

```sh
# in parallel:
npm run watch:build
npm run watch:test
```

For one-time runs:

```sh
npm run build
npm run test
```

## Acknowledgements

- [Namebase Developer docs](https://docs.namebase.io/handshake-login/oidc) for the concept
- [Namebase ID Manager](https://github.com/namebasehq/handshake-id-manager) for code reference and the first strategy
- [@Falci's gist](https://gist.github.com/Falci/8e12be1b9538c4521a3d312a02e4682d) for basic functions and simplified flow
