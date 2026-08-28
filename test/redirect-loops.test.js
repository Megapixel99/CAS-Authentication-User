'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor, silenceErrors,
} = require('./helpers.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });

/**
 * Every entry point in this library can be mounted at a route of the
 * application's choosing, and two of them are documented as belonging at a
 * login route. That makes the route its own redirect target, and a redirect to
 * the current URL in the current state is a loop the browser follows until it
 * gives up. These are the loops that were actually reachable.
 */

test('login mounted as a route does not bounce an authenticated client back to CAS', () => {
  // The README's own `app.get('/login', cas.login)`. login used to redirect to
  // CAS unconditionally: CAS returned the client with a ticket, login ignored
  // it and redirected to CAS again, and CAS minted another ticket every hop.
  const req = makeReq({ session: { cas_user: 'casuser' }, url: '/login', path: '/login' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/'],
    'an authenticated client must be sent onward, not back to the CAS login');
});

test('login mounted as a route validates the ticket CAS returns to it', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = { cas_return_to: '/reports' };
    const req = makeReq({
      session, url: '/login?ticket=ST-1', path: '/login', query: { ticket: 'ST-1' },
    });
    const res = makeRes();
    cas.login(req, res, makeNext());
    await res.settled;
    assert.strictEqual(session.cas_user, 'casuser',
      'the ticket CAS handed back to the login route must be validated');
    assert.deepStrictEqual(res.redirects, ['/reports']);
  } finally {
    await server.close();
  }
});

test('login honours returnTo for an already authenticated client', () => {
  const req = makeReq({
    session: { cas_user: 'casuser' },
    query: { returnTo: '/reports' },
    url: '/login?returnTo=%2Freports',
    path: '/login',
  });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/reports']);
});

test('login still redirects an anonymous client to CAS', () => {
  const req = makeReq({ url: '/login', path: '/login' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).origin, 'https://cas.example.edu');
});

/**
 * The gateway marker travels on the query string precisely so that a client
 * whose session does not persist can still end the check. The redirect that
 * completes a validated ticket dropped the whole query string, marker included,
 * so such a client was sent to CAS again on the very next request - a full
 * round trip per request, for ever, which is the loop the marker exists to stop.
 */
test('a validated ticket keeps the gateway marker when the session did not persist', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const res = makeRes();
    // No cas_return_to: the session did not survive the round trip.
    const req = makeReq({
      session: {},
      url: '/browse?q=cats&cas_gateway=1&ticket=ST-1',
      path: '/browse',
      query: { q: 'cats', cas_gateway: '1', ticket: 'ST-1' },
    });
    cas.gateway(req, res, makeNext());
    await res.settled;
    assert.deepStrictEqual(res.redirects, ['/browse?q=cats&cas_gateway=1'],
      'the marker and the visitor\'s own query must survive the ticket redirect');
  } finally {
    await server.close();
  }
});

test('a gateway check keeps the visitor query string across the CAS round trip', () => {
  // The service URL sent to CAS deliberately carries no application query
  // string, but the destination remembered for the client must, or every
  // visitor to a gateway route silently loses their parameters.
  const req = makeReq({ url: '/browse?q=cats&page=3', path: '/browse' });
  const res = makeRes();
  casOf().gateway(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/browse?q=cats&page=3');
  const service = new URL(res.redirects[0]).searchParams.get('service');
  assert.strictEqual(service, 'https://app.example.edu/browse?cas_gateway=1',
    'the CAS server must not be handed the page parameters');
});

test('a fragment in returnTo is kept for the client and withheld from CAS', () => {
  // CAS appends ?ticket= to the service URL; with a fragment in it the ticket
  // lands inside the fragment, where the application never sees it, and the
  // client arrives unauthenticated to be sent to CAS again.
  const req = makeReq({ query: { returnTo: '/reports#summary' }, url: '/login', path: '/login' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/reports#summary');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/reports');
});

/**
 * A store that cannot write is the other way a login loops: the client is
 * redirected home, arrives with no session, and is bounced to CAS again.
 */
test('a session store that cannot save fails the login instead of looping', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  const restore = silenceErrors();
  try {
    const cas = casFor(server.port);
    const session = {};
    Object.defineProperty(session, 'save', {
      enumerable: false,
      value: (cb) => cb(new Error('store offline')),
    });
    const req = makeReq({
      session, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
    });
    const res = makeRes();
    const next = makeNext();
    cas.bounce(req, res, next);
    await next.settled;
    assert.deepStrictEqual(res.redirects, []);
    assert.match(next.calls[0].message, /store offline/);
  } finally {
    restore();
    await server.close();
  }
});

test('a gateway check restores the visitor query string when CAS returns no ticket', () => {
  // CAS returns the client to the bare service URL, which is not where they
  // asked to be: the check is meant to be invisible, and it was eating every
  // visitor's parameters on the way past.
  const cas = casOf();
  const session = { cas_return_to: '/browse?q=cats&page=3' };
  const req = makeReq({
    session,
    url: '/browse?cas_gateway=1',
    path: '/browse',
    query: { cas_gateway: '1' },
  });
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);
  assert.deepStrictEqual(res.redirects, ['/browse?q=cats&page=3']);
  assert.strictEqual(next.calls.length, 0);
});

test('a gateway pass-through does not redirect when there is nothing to restore', () => {
  // The marked URL is already the destination, so redirecting would be a loop.
  const cas = casOf();
  const req = makeReq({
    session: { cas_return_to: '/browse?cas_gateway=1' },
    url: '/browse?cas_gateway=1',
    path: '/browse',
    query: { cas_gateway: '1' },
  });
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);
  assert.deepStrictEqual(res.redirects, []);
  assert.strictEqual(next.calls.length, 1);
});

test('a client with no session at all still terminates the gateway check', () => {
  // Nothing recorded to restore, so the pass-through stands: one CAS round trip
  // per page view, which is the documented bound.
  const cas = casOf();
  const req = makeReq({
    session: {}, url: '/browse?cas_gateway=1', path: '/browse', query: { cas_gateway: '1' },
  });
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);
  assert.deepStrictEqual(res.redirects, []);
  assert.strictEqual(next.calls.length, 1);
});
