'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor, silenceErrors,
} = require('./helpers.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });
const FLAG = CASAuthentication.GATEWAY_SESSION_FLAG;
const MARKER = CASAuthentication.GATEWAY_QUERY_PARAM;

test('the gateway session flag and query marker are both exported', () => {
  assert.strictEqual(FLAG, 'cas_gateway_attempted');
  assert.strictEqual(MARKER, 'cas_gateway');
});

test('a first gateway request redirects to CAS with gateway=true', () => {
  const cas = casOf();
  const req = makeReq();
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);

  assert.strictEqual(next.calls.length, 0);
  assert.strictEqual(res.redirects.length, 1);
  const target = new URL(res.redirects[0]);
  assert.strictEqual(target.origin + target.pathname, 'https://cas.example.edu/cas/login');
  assert.strictEqual(target.searchParams.get('gateway'), 'true');
  // The service carries the marker, so the check can terminate without a session.
  assert.strictEqual(target.searchParams.get('service'),
    `https://app.example.edu/app?${MARKER}=1`);
  assert.strictEqual(req.session[FLAG], true);
});

test('returning from CAS without a ticket continues unauthenticated', () => {
  const cas = casOf();
  // CAS bounced the client straight back, so the flag is set but no ticket came.
  const req = makeReq({ session: { [FLAG]: true } });
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);

  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(next.calls, [undefined]);
  assert.deepStrictEqual(res.redirects, []);
  assert.deepStrictEqual(res.statuses, []);
  assert.strictEqual(req.session.cas_user, undefined);
});

test('a full gateway cycle with no SSO session redirects exactly once', () => {
  const cas = casOf();
  const session = {};

  const first = makeReq({ session });
  const firstRes = makeRes();
  cas.gateway(first, firstRes, makeNext());
  assert.strictEqual(firstRes.redirects.length, 1);

  // CAS returns the client to the service with no ticket.
  const second = makeReq({ session });
  const secondRes = makeRes();
  const secondNext = makeNext();
  cas.gateway(second, secondRes, secondNext);
  assert.deepStrictEqual(secondRes.redirects, []);
  assert.strictEqual(secondNext.calls.length, 1);

  // And a later request must not bounce again either.
  const third = makeReq({ session });
  const thirdRes = makeRes();
  const thirdNext = makeNext();
  cas.gateway(third, thirdRes, thirdNext);
  assert.deepStrictEqual(thirdRes.redirects, []);
  assert.strictEqual(thirdNext.calls.length, 1);
});

test('an already authenticated session passes through without a gateway check', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' } });
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(res.redirects, []);
  assert.strictEqual(req.session[FLAG], undefined);
});

test('deleting the flag forces a fresh gateway check', () => {
  const cas = casOf();
  const session = { [FLAG]: true };
  cas.gateway(makeReq({ session }), makeRes(), makeNext());

  delete session[FLAG];
  const res = makeRes();
  cas.gateway(makeReq({ session }), res, makeNext());
  assert.strictEqual(res.redirects.length, 1);
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('gateway'), 'true');
});

test('renew takes precedence over gateway, per the CAS protocol', () => {
  const cas = casOf({ renew: true });
  const res = makeRes();
  cas.gateway(makeReq(), res, makeNext());
  const params = new URL(res.redirects[0]).searchParams;
  assert.strictEqual(params.get('renew'), 'true');
  assert.strictEqual(params.has('gateway'), false);
});

test('login never sends gateway', () => {
  const cas = casOf();
  const res = makeRes();
  cas.login(makeReq(), res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).searchParams.has('gateway'), false);
});

test('bounce never sends gateway', () => {
  const cas = casOf();
  const res = makeRes();
  cas.bounce(makeReq(), res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).searchParams.has('gateway'), false);
});

test('gateway honours an explicit returnTo', () => {
  const cas = casOf();
  const req = makeReq({ query: { returnTo: '/reports' } });
  const res = makeRes();
  cas.gateway(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/reports');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    `https://app.example.edu/reports?${MARKER}=1`);
});

test('dev mode satisfies a gateway check without redirecting', () => {
  const cas = casOf({ is_dev_mode: true, dev_mode_user: 'devuser' });
  const req = makeReq();
  const res = makeRes();
  const next = makeNext();
  cas.gateway(req, res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.strictEqual(req.session.cas_user, 'devuser');
  assert.deepStrictEqual(res.redirects, []);
});

test('gateway is bound and works as a detached handler', () => {
  const cas = casOf();
  const { gateway } = cas;
  const res = makeRes();
  assert.doesNotThrow(() => gateway(makeReq(), res, makeNext()));
  assert.strictEqual(res.redirects.length, 1);
});

test('logout clears the gateway flag so the next check runs again', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser', [FLAG]: true } });
  cas.logout(req, makeRes(), makeNext());
  assert.strictEqual(req.session[FLAG], undefined);
});

test('logout that destroys the session takes the gateway flag with it', () => {
  const cas = casOf({ destroy_session: true });
  const req = makeReq({ session: { cas_user: 'casuser', [FLAG]: true } });
  const res = makeRes();
  cas.logout(req, res, makeNext());
  // The whole session is gone, flag included - and logout must not have thrown
  // reaching for it afterwards.
  assert.strictEqual(req.session, undefined);
  assert.deepStrictEqual(res.redirects, ['https://cas.example.edu/cas/logout']);
});

test('a ticket returned from a gateway check authenticates and clears the flag', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const req = makeReq({
      url: '/app?ticket=ST-gw',
      query: { ticket: 'ST-gw' },
      session: { [FLAG]: true, cas_return_to: '/app' },
    });
    const res = makeRes();
    cas.gateway(req, res, makeNext());
    await res.settled;

    assert.strictEqual(req.session.cas_user, 'casuser');
    assert.strictEqual(req.session[FLAG], undefined);
    assert.deepStrictEqual(res.redirects, ['/app']);
  } finally {
    await cas_server.close();
  }
});

test('gateway mode still 401s nothing - it never blocks', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const res = makeRes();
    const next = makeNext();
    cas.gateway(makeReq({ session: { [FLAG]: true } }), res, next);
    assert.deepStrictEqual(res.statuses, []);
    assert.strictEqual(next.calls.length, 1);
    assert.strictEqual(cas_server.requests.length, 0);
  } finally {
    await cas_server.close();
  }
});

test('a client whose session never persists is not redirected in a loop', () => {
  // The regression this guards: with the marker only in the session, a client
  // with blocked cookies bounced between the app and CAS indefinitely.
  const cas = casOf();
  const outcomes = [];
  let query = {};
  for (let i = 0; i < 4; i += 1) {
    const res = makeRes();
    const next = makeNext();
    // A brand new session every request, as if the cookie never came back.
    cas.gateway(makeReq({ session: {}, query }), res, next);
    outcomes.push(res.redirects.length ? 'redirect' : 'next');
    if (res.redirects.length) {
      // Follow CAS back to the service it was given, minus any ticket.
      const service = new URL(new URL(res.redirects[0]).searchParams.get('service'));
      query = Object.fromEntries(service.searchParams.entries());
    }
  }
  // One check, then through - not four redirects.
  assert.deepStrictEqual(outcomes, ['redirect', 'next', 'next', 'next']);
});

test('the query marker alone is enough to pass a gateway check', () => {
  const cas = casOf();
  const res = makeRes();
  const next = makeNext();
  cas.gateway(makeReq({ session: {}, query: { [MARKER]: '1' } }), res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(res.redirects, []);
});

test('a gateway pass-through leaves an application-set userType alone', () => {
  const cas = casOf();
  const session = { [FLAG]: true, userType: 'guest-trial' };
  const next = makeNext();
  cas.gateway(makeReq({ session }), makeRes(), next);
  assert.strictEqual(next.calls.length, 1);
  assert.strictEqual(session.userType, 'guest-trial');
});

test('a gateway redirect still initialises userType', () => {
  const cas = casOf();
  const session = {};
  cas.gateway(makeReq({ session }), makeRes(), makeNext());
  assert.strictEqual(session.userType, '');
});

test('a gateway check whose ticket CAS rejects continues unauthenticated', async () => {
  // Gateway must never block: the visitor never asked to log in.
  const cas_server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const cas = casFor(cas_server.port);
    const session = { [FLAG]: true, cas_return_to: '/' };
    const res = makeRes();
    const next = makeNext();
    cas.gateway(makeReq({
      url: `/?${MARKER}=1&ticket=ST-stale`, path: '/', query: { [MARKER]: '1', ticket: 'ST-stale' }, session,
    }), res, next);
    await next.settled;
    assert.strictEqual(next.calls.length, 1);
    assert.deepStrictEqual(res.statuses, []);
    assert.deepStrictEqual(res.redirects, []);
    assert.strictEqual(session.cas_user, undefined);
  } finally {
    restore();
    await cas_server.close();
  }
});

test('bounce still 401s a rejected ticket - only gateway degrades', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const cas = casFor(cas_server.port);
    const res = makeRes();
    const next = makeNext();
    cas.bounce(makeReq({
      url: '/app?ticket=bad', query: { ticket: 'bad' }, session: { cas_return_to: '/app' },
    }), res, next);
    await res.settled;
    assert.deepStrictEqual(res.statuses, [401]);
    assert.strictEqual(next.calls.length, 0);
  } finally {
    restore();
    await cas_server.close();
  }
});

test('a gateway ticket validates against the marked service URL it was issued for', async () => {
  // CAS rejects a ticket whose service does not match byte for byte, so the
  // marker has to survive into the validation request.
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const session = {};

    const redirectRes = makeRes();
    cas.gateway(makeReq({ session, url: '/', path: '/' }), redirectRes, makeNext());
    const serviceAtLogin = new URL(redirectRes.redirects[0]).searchParams.get('service');
    assert.strictEqual(serviceAtLogin, `http://my-service-host.com/?${MARKER}=1`);

    const ticketRes = makeRes();
    cas.gateway(makeReq({
      session,
      url: `/?${MARKER}=1&ticket=ST-gw`,
      path: '/',
      query: { [MARKER]: '1', ticket: 'ST-gw' },
    }), ticketRes, makeNext());
    await ticketRes.settled;

    const serviceAtValidation = new URL(cas_server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('service');
    assert.strictEqual(serviceAtValidation, serviceAtLogin);
    assert.strictEqual(session.cas_user, 'casuser');
  } finally {
    await cas_server.close();
  }
});
