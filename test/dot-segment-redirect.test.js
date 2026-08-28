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
 * The third instance of this package's oldest bug, and the one the previous two
 * fixes could not have caught: 0.3.0 validated `returnTo` and 0.4.0 rejected a
 * request URL resolving to another origin, and both check the value as it
 * arrives. This one is manufactured by the parser, since `/..//bad.example.com`
 * resolves its dot segment away and leaves this origin with a pathname of
 * `//bad.example.com`, which reaches res.redirect protocol-relative.
 */
const NORMALISED_OFF_ORIGIN = [
  ['a dot segment before a double slash', '/..//bad.example.com'],
  ['a percent-encoded dot segment', '/%2e%2e//bad.example.com'],
  ['dot segments from a deeper path', '/a/b/../../..//bad.example.com'],
  ['a dot segment producing the backslash variant', '/../\\bad.example.com'],
  ['a dot segment with a path attached', '/..//bad.example.com/phish'],
];

NORMALISED_OFF_ORIGIN.forEach(([label, value]) => {
  test(`bounce_redirect refuses ${label} in the request path`, () => {
    const req = makeReq({
      session: { cas_user: 'casuser' }, originalUrl: value, url: value, path: value,
    });
    const res = makeRes();
    casOf().bounce_redirect(req, res, makeNext());
    res.redirects.forEach((location) => {
      assert.ok(!location.startsWith('//') && !location.startsWith('/\\'),
        `${value} produced the protocol-relative Location ${location}`);
      assert.ok(!location.includes('bad.example.com'),
        `${value} must not reach res.redirect, got ${location}`);
    });
  });

  test(`the service URL refuses ${label}`, () => {
    const req = makeReq({ originalUrl: value, url: value, path: value });
    const res = makeRes();
    casOf().login(req, res, makeNext());
    const service = new URL(res.redirects[0]).searchParams.get('service');
    assert.ok(!service.includes('bad.example.com'),
      `${value} must not reach CAS as part of the service URL, got ${service}`);
  });

  test(`the post-login redirect refuses ${label}`, async () => {
    // The dangerous hop: the victim authenticates at the genuine CAS server and
    // is handed to the attacker's site by the redirect that completes it.
    const server = await startCasServer(() => fx.CAS2_SUCCESS);
    try {
      const cas = casFor(server.port);
      const url = `${value}?ticket=ST-1`;
      const res = makeRes();
      cas.bounce(makeReq({
        session: {}, originalUrl: url, url, path: value, query: { ticket: 'ST-1' },
      }), res, makeNext());
      await res.settled;
      res.redirects.forEach((location) => {
        assert.ok(!location.startsWith('//') && !location.startsWith('/\\'),
          `${value} produced the protocol-relative Location ${location}`);
        assert.ok(!location.includes('bad.example.com'),
          `${value} must not survive the CAS round trip, got ${location}`);
      });
    } finally {
      await server.close();
    }
  });
});

test('an ordinary dot segment still resolves normally', () => {
  const req = makeReq({ originalUrl: '/a/b/../c', url: '/a/b/../c', path: '/a/b/../c' });
  assert.strictEqual(casOf()._requestPath(req), '/a/c');
});
