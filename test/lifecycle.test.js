'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor,
} = require('./helpers.js');
const fx = require('./fixtures.js');

const FLAG = CASAuthentication.GATEWAY_SESSION_FLAG;

test('a full bounce login round trip authenticates and then passes through', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port, { session_info: 'cas_info' });
    const session = {};

    // 1. Unauthenticated: redirected to CAS.
    const firstRes = makeRes();
    cas.bounce(makeReq({ session }), firstRes, makeNext());
    assert.strictEqual(firstRes.redirects.length, 1);
    assert.strictEqual(session.cas_return_to, '/app');

    // 2. CAS returns with a ticket: validated and redirected to the saved URL.
    const secondRes = makeRes();
    cas.bounce(makeReq({
      session, url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }), secondRes, makeNext());
    await secondRes.settled;
    assert.deepStrictEqual(secondRes.redirects, ['/app']);
    assert.strictEqual(session.cas_user, 'casuser');

    // 3. Authenticated: straight through to the route handler.
    const thirdRes = makeRes();
    const thirdNext = makeNext();
    cas.bounce(makeReq({ session }), thirdRes, thirdNext);
    assert.strictEqual(thirdNext.calls.length, 1);
    assert.deepStrictEqual(thirdRes.redirects, []);
  } finally {
    await server.close();
  }
});

test('the service sent to CAS login matches the service sent for validation', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = {};

    // Ask to be returned somewhere other than the current path.
    const loginRes = makeRes();
    cas.bounce(makeReq({ session, url: '/app', path: '/app', query: { returnTo: '/dashboard' } }),
      loginRes, makeNext());
    const serviceAtLogin = new URL(loginRes.redirects[0]).searchParams.get('service');
    assert.strictEqual(serviceAtLogin, 'http://my-service-host.com/dashboard');

    // CAS sends the client to that service with a ticket attached.
    const ticketRes = makeRes();
    cas.bounce(makeReq({
      session, url: '/dashboard?ticket=ST-1', path: '/dashboard', query: { ticket: 'ST-1' },
    }), ticketRes, makeNext());
    await ticketRes.settled;

    const serviceAtValidation = new URL(server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('service');
    // CAS rejects a ticket whose service does not match the one it was issued for.
    assert.strictEqual(serviceAtValidation, serviceAtLogin);
    assert.deepStrictEqual(ticketRes.redirects, ['/dashboard']);
  } finally {
    await server.close();
  }
});

test('a session authenticated through bounce also satisfies block and gateway', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = {};
    const res = makeRes();
    cas.bounce(makeReq({ session, url: '/app?ticket=ST-1', query: { ticket: 'ST-1' } }),
      res, makeNext());
    await res.settled;
    assert.strictEqual(session.cas_user, 'casuser');

    const blockNext = makeNext();
    const blockRes = makeRes();
    cas.block(makeReq({ session }), blockRes, blockNext);
    assert.strictEqual(blockNext.calls.length, 1);
    assert.deepStrictEqual(blockRes.statuses, []);

    const gatewayNext = makeNext();
    const gatewayRes = makeRes();
    cas.gateway(makeReq({ session }), gatewayRes, gatewayNext);
    assert.strictEqual(gatewayNext.calls.length, 1);
    assert.deepStrictEqual(gatewayRes.redirects, []);
  } finally {
    await server.close();
  }
});

test('custom session_name and session_info are honoured end to end', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port, { session_name: 'netid', session_info: 'directory' });
    const session = { cas_return_to: '/app' };
    const res = makeRes();
    cas.bounce(makeReq({ session, url: '/app?ticket=ST-1', query: { ticket: 'ST-1' } }),
      res, makeNext());
    await res.settled;

    assert.strictEqual(session.netid, 'casuser');
    assert.strictEqual(session.directory.email, 'casuser@example.edu');
    assert.strictEqual(session.cas_user, undefined);

    // And logout removes exactly those two.
    cas.logout(makeReq({ session }), makeRes(), makeNext());
    assert.strictEqual(session.netid, undefined);
    assert.strictEqual(session.directory, undefined);
  } finally {
    await server.close();
  }
});

test('logging out sends the next bounce back to CAS', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = {};
    const ticketRes = makeRes();
    cas.bounce(makeReq({ session, url: '/app?ticket=ST-1', query: { ticket: 'ST-1' } }),
      ticketRes, makeNext());
    await ticketRes.settled;

    cas.logout(makeReq({ session }), makeRes(), makeNext());

    const afterRes = makeRes();
    const afterNext = makeNext();
    cas.bounce(makeReq({ session }), afterRes, afterNext);
    assert.strictEqual(afterNext.calls.length, 0);
    assert.strictEqual(afterRes.redirects.length, 1);
    assert.match(afterRes.redirects[0], /\/cas\/login\?/);
  } finally {
    await server.close();
  }
});

test('logging out re-arms the gateway check', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = {};

    // Gateway check finds no SSO session, so it passes through.
    cas.gateway(makeReq({ session }), makeRes(), makeNext());
    const passNext = makeNext();
    cas.gateway(makeReq({ session }), makeRes(), passNext);
    assert.strictEqual(passNext.calls.length, 1);

    cas.logout(makeReq({ session }), makeRes(), makeNext());
    assert.strictEqual(session[FLAG], undefined);

    const afterRes = makeRes();
    cas.gateway(makeReq({ session }), afterRes, makeNext());
    assert.strictEqual(afterRes.redirects.length, 1);
  } finally {
    await server.close();
  }
});

test('bounce_redirect delivers an authenticated client to its returnTo', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const session = { cas_return_to: '/authenticate' };
    const ticketRes = makeRes();
    cas.bounce_redirect(makeReq({
      session, url: '/authenticate?ticket=ST-1', query: { ticket: 'ST-1' },
    }), ticketRes, makeNext());
    await ticketRes.settled;
    assert.strictEqual(session.cas_user, 'casuser');

    // Now authenticated, a returnTo takes them onward.
    const onwardRes = makeRes();
    cas.bounce_redirect(makeReq({ session, query: { returnTo: '/reports' } }),
      onwardRes, makeNext());
    assert.deepStrictEqual(onwardRes.redirects, ['/reports']);
  } finally {
    await server.close();
  }
});

test('dev mode authenticates every middleware and survives a logout cycle', () => {
  const cas = new CASAuthentication({
    cas_url: 'https://cas.example.edu/cas',
    service_url: 'https://app.example.edu',
    is_dev_mode: true,
    dev_mode_user: 'devuser',
  });
  const session = {};
  ['bounce', 'block', 'gateway'].forEach((name) => {
    const next = makeNext();
    cas[name](makeReq({ session }), makeRes(), next);
    assert.strictEqual(next.calls.length, 1, `${name} should pass through in dev mode`);
    assert.strictEqual(session.cas_user, 'devuser');
  });

  cas.logout(makeReq({ session }), makeRes(), makeNext());
  assert.strictEqual(session.cas_user, undefined);

  // Dev mode re-authenticates immediately.
  const next = makeNext();
  cas.bounce(makeReq({ session }), makeRes(), next);
  assert.strictEqual(next.calls.length, 1);
  assert.strictEqual(session.cas_user, 'devuser');
});

test('a failed validation leaves a clean session for a later retry', async () => {
  const failing = await startCasServer(() => fx.CAS2_FAILURE);
  const succeeding = await startCasServer(() => fx.CAS2_SUCCESS);
  const originalError = console.error;
  console.error = () => {};
  try {
    const session = { cas_return_to: '/app' };
    const failCas = casFor(failing.port);
    const failRes = makeRes();
    failCas.bounce(makeReq({ session, url: '/app?ticket=bad', query: { ticket: 'bad' } }),
      failRes, makeNext());
    await failRes.settled;
    assert.deepStrictEqual(failRes.statuses, [401]);
    assert.strictEqual(session.cas_user, undefined);

    // A subsequent valid ticket still works on the same session.
    const okCas = casFor(succeeding.port);
    const okRes = makeRes();
    okCas.bounce(makeReq({ session, url: '/app?ticket=ST-good', query: { ticket: 'ST-good' } }),
      okRes, makeNext());
    await okRes.settled;
    assert.strictEqual(session.cas_user, 'casuser');
  } finally {
    console.error = originalError;
    await failing.close();
    await succeeding.close();
  }
});
