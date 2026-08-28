'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const https = require('https');
const { CASAuthentication, silenceErrors, collectingLogger } = require('./helpers.js');

const MINIMAL = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };

test('constructor rejects a missing or non-object configuration', () => {
  assert.throws(() => new CASAuthentication(), /valid configuration object/);
  assert.throws(() => new CASAuthentication(null), /valid configuration object/);
  assert.throws(() => new CASAuthentication('cas.example.edu'), /valid configuration object/);
});

test('constructor requires cas_url and service_url', () => {
  assert.throws(() => new CASAuthentication({ service_url: 'https://app.example.edu' }),
    /requires a cas_url parameter/);
  assert.throws(() => new CASAuthentication({ cas_url: 'https://cas.example.edu/cas' }),
    /requires a service_url parameter/);
});

test('constructor rejects an unsupported CAS version', () => {
  assert.throws(() => new CASAuthentication({ ...MINIMAL, cas_version: '4.0' }),
    /The supplied CAS version \("4\.0"\) is not supported/);
});

test('constructor applies documented defaults', () => {
  const cas = new CASAuthentication({ ...MINIMAL });
  assert.strictEqual(cas.cas_version, '3.0');
  assert.strictEqual(cas.renew, false);
  assert.strictEqual(cas.is_dev_mode, false);
  assert.strictEqual(cas.dev_mode_user, '');
  assert.deepStrictEqual(cas.dev_mode_info, {});
  assert.strictEqual(cas.session_name, 'cas_user');
  assert.strictEqual(cas.session_info, false);
  assert.strictEqual(cas.destroy_session, false);
});

test('constructor coerces boolean options', () => {
  const restore = silenceErrors();
  const cas = new CASAuthentication({
    ...MINIMAL, renew: 'yes', is_dev_mode: 1, dev_mode_user: 'devuser', destroy_session: 0,
  });
  restore();
  assert.strictEqual(cas.renew, true);
  assert.strictEqual(cas.is_dev_mode, true);
  assert.strictEqual(cas.destroy_session, false);
});

/**
 * Dev mode authenticates every request as one user without contacting CAS, so
 * a deployment that reaches production with it on is wide open. It used to
 * arrive in total silence on every channel.
 */
test('dev mode announces itself on the logger', () => {
  const logger = collectingLogger();
  new CASAuthentication({ ...MINIMAL, is_dev_mode: true, dev_mode_user: 'devuser', logger });
  assert.ok(logger.messages().some((m) => /DEV MODE/.test(m)),
    `expected a dev mode warning, got ${JSON.stringify(logger.messages())}`);
});

test('dev mode without a dev_mode_user is refused', () => {
  // The default was '', which the library itself rejects when a real CAS server
  // sends it: authenticated as far as the middleware is concerned, anonymous to
  // every `if (req.session.cas_user)` in the application.
  assert.throws(() => new CASAuthentication({ ...MINIMAL, is_dev_mode: true }),
    /non-empty dev_mode_user/);
});

test('each CAS version selects the right validation endpoint', () => {
  const uris = {
    '1.0': '/validate',
    '2.0': '/serviceValidate',
    '3.0': '/p3/serviceValidate',
    'saml1.1': '/samlValidate',
  };
  Object.entries(uris).forEach(([version, uri]) => {
    const cas = new CASAuthentication({ ...MINIMAL, cas_version: version });
    assert.strictEqual(cas._validateUri, uri, `${version} should validate at ${uri}`);
    assert.strictEqual(typeof cas._validate, 'function');
  });
});

test('the request client follows the cas_url protocol', () => {
  assert.strictEqual(new CASAuthentication({ ...MINIMAL }).request_client, https);
  assert.strictEqual(new CASAuthentication({
    ...MINIMAL, cas_url: 'http://cas.example.edu/cas',
  }).request_client, http);
});

test('cas_url is split into host and path', () => {
  const cas = new CASAuthentication({ ...MINIMAL, cas_url: 'https://cas.example.edu/idp/cas' });
  assert.strictEqual(cas.cas_host, 'cas.example.edu');
  assert.strictEqual(cas.cas_path, '/idp/cas');
});

test('session_info is ignored for CAS 1.0, which cannot supply attributes', () => {
  const v1 = new CASAuthentication({ ...MINIMAL, cas_version: '1.0', session_info: 'info' });
  assert.strictEqual(v1.session_info, false);
  const v3 = new CASAuthentication({ ...MINIMAL, cas_version: '3.0', session_info: 'info' });
  assert.strictEqual(v3.session_info, 'info');
});

test('routing methods are bound so they can be passed as bare handlers', () => {
  const cas = new CASAuthentication({ ...MINIMAL });
  ['bounce', 'bounce_redirect', 'block', 'logout', 'login'].forEach((name) => {
    const detached = cas[name];
    assert.strictEqual(typeof detached, 'function');
    // Would throw on `this.session_name` if the binding were missing.
    assert.doesNotThrow(() => detached.call(undefined,
      { session: { cas_user: 'x' }, query: {}, url: '/app', path: '/app' },
      { redirect() {}, sendStatus() {} }, () => {}));
  });
});

test('an explicit port in cas_url is used', () => {
  assert.strictEqual(new CASAuthentication({
    ...MINIMAL, cas_url: 'https://cas.example.edu:8443/cas',
  }).cas_port, 8443);
  assert.strictEqual(new CASAuthentication({
    ...MINIMAL, cas_url: 'http://cas.example.edu:8080/cas',
  }).cas_port, 8080);
});

test('cas_port is a number, not the string url.parse produced', () => {
  const cas = new CASAuthentication({ ...MINIMAL, cas_url: 'https://cas.example.edu:8443/cas' });
  assert.strictEqual(typeof cas.cas_port, 'number');
});

test('cas_port falls back to the protocol default when no port is given', () => {
  assert.strictEqual(new CASAuthentication({
    ...MINIMAL, cas_url: 'https://cas.example.edu/cas',
  }).cas_port, 443);
  assert.strictEqual(new CASAuthentication({
    ...MINIMAL, cas_url: 'http://cas.example.edu/cas',
  }).cas_port, 80);
});
