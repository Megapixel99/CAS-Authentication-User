'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor,
} = require('./helpers.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });

/**
 * returnTo is not the only client-controlled value that reaches res.redirect.
 * The request path does too, by way of _requestPath, and a path is not
 * automatically same-origin: `//host` is protocol-relative and `/\host` is the
 * variant browsers normalise to it. The legacy parser reported both as a
 * *pathname*, so redirecting to it left the site.
 *
 * Unlike the returnTo flow, this one needs no CAS round trip: an already
 * authenticated client on a bounce_redirect route is redirected straight away.
 */
const OFF_ORIGIN_PATHS = [
  ['a protocol-relative path', '//bad.example.com/phish'],
  ['a backslash variant', '/\\bad.example.com'],
  ['a backslash path with a query', '/\\bad.example.com?a=1'],
];

OFF_ORIGIN_PATHS.forEach(([label, value]) => {
  test(`bounce_redirect refuses ${label} in the request path`, () => {
    const req = makeReq({
      session: { cas_user: 'casuser' }, originalUrl: value, url: value, path: value,
    });
    const res = makeRes();
    casOf().bounce_redirect(req, res, makeNext());
    assert.deepStrictEqual(res.redirects, ['/'],
      `${value} must not become a redirect target`);
  });

  test(`the login service URL refuses ${label}`, () => {
    const req = makeReq({ originalUrl: value, url: value, path: value });
    const res = makeRes();
    casOf().login(req, res, makeNext());
    const service = new URL(res.redirects[0]).searchParams.get('service');
    assert.ok(service.startsWith('https://app.example.edu/'), `service was ${service}`);
    assert.ok(!service.includes('bad.example.com'),
      `${value} must not reach CAS as part of the service URL, got ${service}`);
  });

  test(`the ticket service URL refuses ${label}`, () => {
    const req = makeReq({ originalUrl: value, url: value, path: value });
    assert.strictEqual(casOf()._serviceForRequest(req), 'https://app.example.edu/');
  });
});

test('an ordinary path with repeated slashes is left alone', () => {
  const req = makeReq({ originalUrl: '/a//b', url: '/a//b', path: '/a//b' });
  assert.strictEqual(casOf()._requestPath(req), '/a//b');
});

/**
 * CAS honours a ticket only for the exact service string it issued it for, so
 * the encoding of the service parameter is load-bearing. URLSearchParams would
 * serialise a space as `+` and percent-encode `~!*()`; these pin the encoding
 * that CAS servers have actually been receiving.
 */
test('the query encoder reproduces what CAS servers were already sent', () => {
  // These are the exact strings the legacy url.format produced. URLSearchParams
  // would render the space as `+` and percent-encode `~!*()`, so a CAS server
  // would see a different service string than the one the ticket was issued
  // for and reject it.
  assert.strictEqual(
    CASAuthentication.formatQuery({ service: 'https://app.example.edu/a b', gateway: true }),
    'service=https%3A%2F%2Fapp.example.edu%2Fa%20b&gateway=true',
  );
  assert.strictEqual(
    CASAuthentication.formatQuery({ service: 'https://app.example.edu/~t!*()' }),
    'service=https%3A%2F%2Fapp.example.edu%2F~t!*()',
  );
  assert.strictEqual(
    CASAuthentication.formatQuery({ TARGET: 'https://app.example.edu/p?a=1&b=2', ticket: '' }),
    'TARGET=https%3A%2F%2Fapp.example.edu%2Fp%3Fa%3D1%26b%3D2&ticket=',
  );
});

test('a query string reaches the validation request byte for byte', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const raw = '/p?keep=%2F%2Fx&sp=a%20b&tilde=~';
    const req = makeReq({ originalUrl: `${raw}&ticket=ST-1`, url: `${raw}&ticket=ST-1`, path: '/p' });
    await new Promise((resolve) => {
      cas._validateTicket({ ticket: 'ST-1', service: cas._serviceForRequest(req) }, resolve);
    });
    const sent = new URL(server.requests[0].url, 'http://x').searchParams.get('service');
    assert.strictEqual(sent, 'http://my-service-host.com/p?keep=%2F%2Fx&sp=a%20b&tilde=~');
  } finally {
    await server.close();
  }
});

test('a cas_url that is not a URL is refused by the constructor', () => {
  assert.throws(() => casOf({ cas_url: 'not a url' }), /not a valid URL/);
});

test('a cas_url with an explicit default port still resolves to that port', () => {
  assert.strictEqual(casOf({ cas_url: 'https://cas.example.edu:443/cas' }).cas_port, 443);
  assert.strictEqual(casOf({ cas_url: 'http://cas.example.edu:80/cas' }).cas_port, 80);
});

