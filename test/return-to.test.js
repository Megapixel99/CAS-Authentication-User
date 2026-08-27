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
 * returnTo comes from the client, so it must never be able to carry them to
 * another origin. An attacker who can choose the post-login destination has a
 * credential-phishing flow: the victim logs in at the real CAS server and lands
 * on a lookalike.
 */
const OFF_SITE = [
  ['an absolute http URL', 'http://bad.example.com/phish'],
  ['an absolute https URL', 'https://bad.example.com/phish'],
  ['a protocol-relative path', '//bad.example.com/phish'],
  ['a backslash variant', '/\\bad.example.com'],
  ['a double backslash variant', '\\\\bad.example.com'],
  ['a javascript scheme', 'javascript:alert(1)'],
  ['a data scheme', 'data:text/html,<script>alert(1)</script>'],
  ['a scheme-relative URL with credentials', '//user:pass@bad.example.com'],
];

OFF_SITE.forEach(([label, value]) => {
  test(`bounce_redirect refuses ${label}`, () => {
    const req = makeReq({
      session: { cas_user: 'casuser' }, query: { returnTo: value }, url: '/authenticate', path: '/authenticate',
    });
    const res = makeRes();
    casOf().bounce_redirect(req, res, makeNext());
    assert.deepStrictEqual(res.redirects, ['/authenticate'],
      `${value} must not become a redirect target`);
  });

  test(`login refuses ${label}`, () => {
    const req = makeReq({ query: { returnTo: value }, url: '/app', path: '/app' });
    const res = makeRes();
    casOf().login(req, res, makeNext());
    assert.strictEqual(req.session.cas_return_to, '/app');
    // The service handed to CAS must stay on our own origin too.
    assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
      'https://app.example.edu/app');
  });
});

test('a safe absolute path is honoured', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' }, query: { returnTo: '/reports/2026' }, url: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/reports/2026']);
});

test('a safe path with a query string is honoured', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' }, query: { returnTo: '/reports?year=2026' }, url: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/reports?year=2026']);
});

test('an off-site returnTo cannot survive a full login round trip', async () => {
  // The dangerous path: the victim authenticates against the real CAS server and
  // is then handed to the attacker's site.
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const session = {};
    cas.bounce(makeReq({
      session, query: { returnTo: 'https://bad.example.com/phish' }, url: '/app', path: '/app',
    }), makeRes(), makeNext());
    assert.strictEqual(session.cas_return_to, '/app');

    const res = makeRes();
    cas.bounce(makeReq({
      session, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
    }), res, makeNext());
    await res.settled;
    assert.deepStrictEqual(res.redirects, ['/app']);
  } finally {
    await cas_server.close();
  }
});

test('bounce_redirect without returnTo keeps the current path and query', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' }, url: '/authenticate?flow=sso', path: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/authenticate?flow=sso']);
});

test('bounce_redirect keeps a router mount prefix', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' },
    originalUrl: '/portal/authenticate?flow=sso',
    url: '/authenticate?flow=sso',
    path: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/portal/authenticate?flow=sso']);
});

test('a repeated returnTo is refused rather than coerced', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' },
    query: { returnTo: ['/a', 'https://bad.example.com'] },
    url: '/authenticate',
    path: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/authenticate']);
});
