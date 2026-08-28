'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor, collectingLogger,
  runStrategy, silenceErrors,
} = require('./helpers.js');
const Strategy = require('../strategy.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });

/**
 * regenerate_session defaults to true because an attacker who plants a session
 * cookie before the victim logs in otherwise holds a handle on the authenticated
 * session afterwards. A session middleware without regenerate() cannot offer the
 * defence, and the documented fallback happened in silence, so an application
 * that had asked for the protection could not learn it was not getting it.
 */
test('a session middleware without regenerate() says so on the logger', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger });
    const res = makeRes();
    // A hand-rolled session layer: a plain object, no regenerate().
    cas.bounce(makeReq({
      session: {}, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
    }), res, makeNext());
    await res.settled;
    assert.ok(logger.messages().some((m) => /session fixation/.test(m)),
      `expected a fixation warning, got ${JSON.stringify(logger.messages())}`);
  } finally {
    await server.close();
  }
});

test('no warning when regenerate_session is switched off deliberately', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger, regenerate_session: false });
    const res = makeRes();
    cas.bounce(makeReq({
      session: {}, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
    }), res, makeNext());
    await res.settled;
    assert.ok(!logger.messages().some((m) => /session fixation/.test(m)),
      'an application that opted out should not be nagged');
  } finally {
    await server.close();
  }
});

/**
 * Passport keeps the authenticated user under its own session key, which
 * cas.logout left in place, so a client who signed in through the bundled
 * strategy was shown the CAS logout page while every route behind Passport
 * carried on treating them as signed in.
 */
test('logout clears the Passport session too', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser', passport: { user: 'casuser' } } });
  let loggedOut = false;
  req.logout = (cb) => {
    loggedOut = true;
    delete req.session.passport;
    cb();
  };
  cas.logout(req, makeRes(), makeNext());
  assert.ok(loggedOut, 'req.logout must be called when Passport is present');
  assert.strictEqual(req.session.passport, undefined);
  assert.strictEqual(req.session.cas_user, undefined);
});

test('logout works unchanged when Passport is not installed', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' } });
  const res = makeRes();
  cas.logout(req, res, makeNext());
  assert.strictEqual(req.session.cas_user, undefined);
  assert.deepStrictEqual(res.redirects, ['https://cas.example.edu/cas/logout']);
});

/**
 * A verify callback that throws is the application's bug, but the throw used to
 * be caught by the response parser in index.js and dropped, so Passport was told
 * nothing at all: no success, no fail, no error, and a request that never
 * answered.
 */
test('a verify callback that throws reaches Passport error()', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const strategy = new Strategy({
      cas_url: `http://127.0.0.1:${server.port}/cas`,
      service_url: 'http://my-service-host.com',
    }, () => { throw new Error('verify exploded'); });
    const outcome = await runStrategy(strategy, makeReq({
      session: {}, url: '/auth?ticket=ST-1', path: '/auth', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'error');
    assert.match(outcome.err.message, /verify exploded/);
  } finally {
    await server.close();
  }
});

test('the strategy prefers req.hostname, as the middleware does', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const strategy = new Strategy({
      cas_url: `http://127.0.0.1:${server.port}/cas`,
      service_url: 'http://my-service-host.com',
      cas_version: 'saml1.1',
    });
    await runStrategy(strategy, makeReq({
      session: {},
      url: '/auth?ticket=ST-1',
      path: '/auth',
      query: { ticket: 'ST-1' },
      hostname: 'my-service-host.com',
      host: undefined,
    }));
    assert.match(server.requests[0].body, /RequestID="_my-service-host\.com\./,
      'req.hostname must be used to label the SAML RequestID');
  } finally {
    await server.close();
  }
});

/**
 * cas_url and service_url are the two required options, and a mistake in either
 * surfaced a long way from the cause: a request to the wrong host, or a 404 with
 * a doubled slash in it.
 */
test('a cas_url with a scheme that is not http or https is refused', () => {
  assert.throws(() => casOf({ cas_url: 'htps://cas.example.edu/cas' }),
    /http or https URL/);
  assert.throws(() => casOf({ cas_url: 'javascript:alert(1)' }),
    /http or https URL/);
});

test('service_url is validated rather than concatenated blindly', () => {
  assert.throws(() => casOf({ service_url: 'app.example.edu' }), /not a valid URL/);
  assert.throws(() => casOf({ service_url: 'ftp://app.example.edu' }), /http or https URL/);
});

test('a trailing slash on service_url does not produce a doubled slash', () => {
  const cas = casOf({ service_url: 'https://app.example.edu/' });
  const res = makeRes();
  cas.login(makeReq({ url: '/dashboard', path: '/dashboard' }), res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/dashboard');
});

test('a trailing slash on cas_url does not produce a doubled validate path', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = new CASAuthentication({
      cas_url: `http://127.0.0.1:${server.port}/`,
      service_url: 'http://my-service-host.com',
    });
    await cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' });
    assert.ok(server.requests[0].url.startsWith('/p3/serviceValidate'),
      `expected a single-slash validate path, got ${server.requests[0].url}`);
  } finally {
    await server.close();
  }
});

test('the timeout values that used to fail open are refused', () => {
  // Number(null), Number(false) and Number([]) are all 0, the value that means
  // "wait for ever", so the malformed options that got through were exactly the
  // ones that disabled the timeout.
  [null, false, [], {}, 'abc'].forEach((value) => {
    assert.throws(() => casOf({ timeout: value }), /non-negative number/,
      `timeout: ${JSON.stringify(value)} must be refused`);
  });
  assert.strictEqual(casOf({ timeout: 0 }).timeout, 0);
  assert.strictEqual(casOf({ timeout: '5000' }).timeout, 5000);
});

test('max_response_bytes is validated and defaults to something sane', () => {
  const restore = silenceErrors();
  assert.strictEqual(casOf().max_response_bytes, 1048576);
  assert.strictEqual(casOf({ max_response_bytes: 0 }).max_response_bytes, 0);
  assert.throws(() => casOf({ max_response_bytes: -1 }), /non-negative number/);
  assert.throws(() => casOf({ max_response_bytes: 'big' }), /non-negative number/);
  restore();
});
