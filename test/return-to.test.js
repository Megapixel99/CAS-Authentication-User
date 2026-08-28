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
    // The site root, not the request path. Falling back to the request path
    // sent the client to the route they were already on, in the same state,
    // which the browser followed straight back into this handler for ever - so
    // every value in this list turned a refusal into a redirect loop.
    assert.deepStrictEqual(res.redirects, ['/'],
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

/**
 * bounce_redirect exists to send an authenticated client somewhere else, and
 * `returnTo` is how it is told where. Without one there is no destination, and
 * the previous answer - the URL the client is already at - was a redirect to
 * this same handler, which redirected again, for ever. Every browser that
 * followed it gave up with a redirect-loop error, on the plainest possible
 * request: GET /authenticate with no query string at all.
 */
test('bounce_redirect without returnTo goes to the site root rather than looping', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' }, url: '/authenticate?flow=sso', path: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/']);
});

test('bounce_redirect at the site root passes the request through instead', () => {
  // Redirecting to `/` from `/` is the same loop by another name, so the
  // authenticated request is handed to the application instead.
  const req = makeReq({ session: { cas_user: 'casuser' }, url: '/', path: '/' });
  const res = makeRes();
  const next = makeNext();
  casOf().bounce_redirect(req, res, next);
  assert.deepStrictEqual(res.redirects, []);
  assert.strictEqual(next.calls.length, 1);
});

test('bounce_redirect keeps a router mount prefix in an honoured returnTo', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' },
    query: { returnTo: '/portal/reports' },
    originalUrl: '/portal/authenticate?flow=sso',
    url: '/authenticate?flow=sso',
    path: '/authenticate',
  });
  const res = makeRes();
  casOf().bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/portal/reports']);
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
  assert.deepStrictEqual(res.redirects, ['/']);
});
