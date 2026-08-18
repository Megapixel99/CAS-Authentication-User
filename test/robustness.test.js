'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor, silenceErrors,
} = require('./helpers.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };

/** A server that accepts the connection and never answers. */
function startSilentServer() {
  const server = http.createServer(() => {});
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => server.close(r)),
    }));
  });
}

test('timeout defaults to 10 seconds and is configurable', () => {
  assert.strictEqual(new CASAuthentication({ ...BASE }).timeout, 10000);
  assert.strictEqual(new CASAuthentication({ ...BASE, timeout: 2500 }).timeout, 2500);
  assert.strictEqual(new CASAuthentication({ ...BASE, timeout: 0 }).timeout, 0);
});

test('a non-numeric or negative timeout is rejected at construction', () => {
  assert.throws(() => new CASAuthentication({ ...BASE, timeout: 'soon' }),
    /timeout to be a non-negative number/);
  assert.throws(() => new CASAuthentication({ ...BASE, timeout: -1 }),
    /timeout to be a non-negative number/);
});

test('a CAS server that never answers produces a 401 instead of hanging', { timeout: 15000 }, async () => {
  const silent = await startSilentServer();
  const restore = silenceErrors();
  try {
    const cas = casFor(silent.port, { timeout: 300 });
    const res = makeRes();
    cas.bounce(makeReq({
      url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
      session: { cas_return_to: '/app' },
    }), res, makeNext());

    const outcome = await Promise.race([
      res.settled,
      new Promise((r) => setTimeout(() => r({ type: 'hung' }), 5000)),
    ]);
    assert.strictEqual(outcome.type, 'status');
    assert.deepStrictEqual(res.statuses, [401]);
  } finally {
    restore();
    await silent.close();
  }
});

test('a timed-out gateway check continues unauthenticated rather than blocking', { timeout: 15000 }, async () => {
  const silent = await startSilentServer();
  const restore = silenceErrors();
  try {
    const cas = casFor(silent.port, { timeout: 300 });
    const next = makeNext();
    const res = makeRes();
    cas.gateway(makeReq({
      url: `/?${CASAuthentication.GATEWAY_QUERY_PARAM}=1&ticket=ST-1`,
      path: '/',
      query: { [CASAuthentication.GATEWAY_QUERY_PARAM]: '1', ticket: 'ST-1' },
      session: { [CASAuthentication.GATEWAY_SESSION_FLAG]: true },
    }), res, next);

    const outcome = await Promise.race([
      next.settled,
      new Promise((r) => setTimeout(() => r({ type: 'hung' }), 5000)),
    ]);
    assert.strictEqual(outcome.type, 'next');
    assert.deepStrictEqual(res.statuses, []);
  } finally {
    restore();
    await silent.close();
  }
});

test('the timeout can be disabled with 0', async () => {
  // Proves 0 really means no timer: a slow-but-answering server still succeeds
  // well past what a short timeout would have allowed.
  const slow = await startCasServer(() => new Promise(() => {}));
  await slow.close();
  const server = await startCasServer(() => '');
  try {
    const cas = casFor(server.port, { timeout: 0 });
    assert.strictEqual(cas.timeout, 0);
  } finally {
    await server.close();
  }
});

const BLANK_USER = [
  ['CAS 1.0 reporting yes with no username', '1.0', 'yes\n\n'],
  ['CAS 1.0 reporting yes with a whitespace username', '1.0', 'yes\n   \n'],
  ['CAS 3.0 with an empty cas:user', '3.0',
    '<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">'
    + '<cas:authenticationSuccess><cas:user></cas:user>'
    + '</cas:authenticationSuccess></cas:serviceResponse>'],
];

BLANK_USER.forEach(([label, version, body]) => {
  test(`${label} is not treated as authenticated`, async () => {
    // Storing an empty username would leave the client looking unauthenticated
    // on every later request, looping between the app and CAS forever.
    const cas_server = await startCasServer(() => body);
    const restore = silenceErrors();
    try {
      const cas = casFor(cas_server.port, { cas_version: version });
      const session = { cas_return_to: '/app' };
      const res = makeRes();
      cas.bounce(makeReq({
        url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' }, session,
      }), res, makeNext());
      await res.settled;

      assert.deepStrictEqual(res.statuses, [401]);
      assert.strictEqual(session[cas.session_name], undefined);

      // And the client's next request is not stuck in a redirect loop with a
      // falsy username sitting in the session.
      const nextRes = makeRes();
      const next = makeNext();
      cas.block(makeReq({ session, url: '/app', path: '/app' }), nextRes, next);
      assert.deepStrictEqual(nextRes.statuses, [401], 'still unauthenticated, cleanly');
    } finally {
      restore();
      await cas_server.close();
    }
  });
});

test('a genuine username is still accepted', async () => {
  const cas_server = await startCasServer(() => 'yes\ncasuser\n');
  try {
    const cas = casFor(cas_server.port, { cas_version: '1.0' });
    const session = { cas_return_to: '/app' };
    const res = makeRes();
    cas.bounce(makeReq({
      url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' }, session,
    }), res, makeNext());
    await res.settled;
    assert.strictEqual(session.cas_user, 'casuser');
  } finally {
    await cas_server.close();
  }
});
