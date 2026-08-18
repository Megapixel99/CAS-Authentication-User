'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, startCasServer, runStrategy, silenceErrors,
} = require('./helpers.js');
const Strategy = require('../strategy.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const FLAG = CASAuthentication.GATEWAY_SESSION_FLAG;
const MARKER = CASAuthentication.GATEWAY_QUERY_PARAM;

/** A strategy pointed at a local fake CAS server. */
function strategyFor(port, options, verify) {
  const cas = new CASAuthentication({
    cas_url: `http://127.0.0.1:${port}/cas`,
    service_url: 'http://my-service-host.com',
    ...options,
  });
  return new Strategy({ cas, ...options }, verify);
}

test('the strategy is exported both directly and as .Strategy', () => {
  assert.strictEqual(typeof Strategy, 'function');
  assert.strictEqual(Strategy.Strategy, Strategy);
});

test('the strategy defaults to the name "cas" and accepts an override', () => {
  assert.strictEqual(new Strategy({ ...BASE }).name, 'cas');
  assert.strictEqual(new Strategy({ ...BASE, name: 'university' }).name, 'university');
});

test('the strategy builds its own CASAuthentication from plain options', () => {
  const strategy = new Strategy({ ...BASE, cas_version: '2.0' });
  assert.ok(strategy.cas instanceof CASAuthentication);
  assert.strictEqual(strategy.cas._validateUri, '/serviceValidate');
});

test('the strategy reuses an existing CASAuthentication instance', () => {
  const cas = new CASAuthentication({ ...BASE });
  assert.strictEqual(new Strategy({ cas }).cas, cas);
});

test('the strategy rejects an invalid configuration', () => {
  assert.throws(() => new Strategy('nope'), /valid configuration object/);
  assert.throws(() => new Strategy({ ...BASE }, 'not a function'),
    /verify callback must be a function/);
});

test('a verify callback may be passed as the only argument', () => {
  // Only valid alongside an options-free construction, which then has no cas_url.
  assert.throws(() => new Strategy(() => {}), /requires a cas_url parameter/);
});

test('a request with no ticket is redirected to the CAS login', async () => {
  const strategy = new Strategy({ ...BASE });
  const outcome = await runStrategy(strategy, makeReq({ url: '/app' }));
  assert.strictEqual(outcome.type, 'redirect');
  const target = new URL(outcome.location);
  assert.strictEqual(target.origin + target.pathname, 'https://cas.example.edu/cas/login');
  assert.strictEqual(target.searchParams.get('service'), 'https://app.example.edu/app');
  assert.strictEqual(target.searchParams.has('gateway'), false);
});

test('the redirect service URL does not carry the page query string to CAS', async () => {
  // Page parameters must not reach the CAS server or its access logs, and the
  // core middleware does not send them either.
  const strategy = new Strategy({ ...BASE });
  const outcome = await runStrategy(strategy, makeReq({
    url: '/reset?token=s3cret&q=cats', path: '/reset',
  }));
  assert.strictEqual(new URL(outcome.location).searchParams.get('service'),
    'https://app.example.edu/reset');
});

test('the core middleware and the strategy agree on the redirect service URL', async () => {
  const cas = new CASAuthentication({ ...BASE });
  const req = makeReq({ url: '/reset?token=s3cret', path: '/reset' });
  const res = { redirects: [], redirect(l) { this.redirects.push(l); }, sendStatus() {} };
  cas.bounce(req, res, () => {});
  const coreService = new URL(res.redirects[0]).searchParams.get('service');

  const outcome = await runStrategy(new Strategy({ cas }), makeReq({
    url: '/reset?token=s3cret', path: '/reset',
  }));
  assert.strictEqual(new URL(outcome.location).searchParams.get('service'), coreService);
});

test('renew is carried through to the login redirect', async () => {
  const outcome = await runStrategy(new Strategy({ ...BASE, renew: true }), makeReq());
  assert.strictEqual(new URL(outcome.location).searchParams.get('renew'), 'true');
});

test('a valid ticket succeeds with a CAS profile when no verify callback is given', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const outcome = await runStrategy(strategyFor(server.port), makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'success');
    assert.deepStrictEqual(outcome.user, {
      provider: 'cas',
      id: 'casuser',
      user: 'casuser',
      attributes: { email: 'casuser@example.edu', displayname: 'Cas User' },
    });
  } finally {
    await server.close();
  }
});

test('attributes default to an empty object when CAS releases none', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS_NO_ATTRS);
  try {
    const outcome = await runStrategy(strategyFor(server.port), makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.deepStrictEqual(outcome.user.attributes, {});
  } finally {
    await server.close();
  }
});

test('the verify callback receives the profile and can map it to a local user', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const seen = [];
    const strategy = strategyFor(server.port, {}, (profile, done) => {
      seen.push(profile);
      done(null, { localId: 42, netid: profile.user }, { source: 'directory' });
    });
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'success');
    assert.deepStrictEqual(outcome.user, { localId: 42, netid: 'casuser' });
    assert.deepStrictEqual(outcome.info, { source: 'directory' });
    assert.strictEqual(seen.length, 1);
    assert.strictEqual(seen[0].user, 'casuser');
  } finally {
    await server.close();
  }
});

test('passReqToCallback puts req in front of the profile', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const args = [];
    const strategy = strategyFor(server.port, { passReqToCallback: true }, (req, profile, done) => {
      args.push([req, profile]);
      done(null, { netid: profile.user });
    });
    const req = makeReq({ url: '/app?ticket=ST-1', query: { ticket: 'ST-1' } });
    const outcome = await runStrategy(strategy, req);
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(args[0][0], req);
    assert.strictEqual(args[0][1].user, 'casuser');
  } finally {
    await server.close();
  }
});

test('a verify callback that yields no user fails with its info', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const strategy = strategyFor(server.port, {},
      (profile, done) => done(null, false, { message: 'not enrolled' }));
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'fail');
    assert.deepStrictEqual(outcome.challenge, { message: 'not enrolled' });
  } finally {
    await server.close();
  }
});

test('a verify callback error surfaces through error(), not fail()', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const boom = new Error('directory unavailable');
    const strategy = strategyFor(server.port, {}, (profile, done) => done(boom));
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'error');
    assert.strictEqual(outcome.err, boom);
  } finally {
    await server.close();
  }
});

test('a rejected ticket fails with 401 and the CAS reason', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const outcome = await runStrategy(strategyFor(server.port), makeReq({
      url: '/app?ticket=bad', query: { ticket: 'bad' },
    }));
    assert.strictEqual(outcome.type, 'fail');
    assert.strictEqual(outcome.status, 401);
    assert.match(outcome.challenge.message, /INVALID_TICKET/);
  } finally {
    restore();
    await server.close();
  }
});

test('an unreachable CAS server fails rather than hanging', async () => {
  const server = await startCasServer(() => '');
  const { port } = server;
  await server.close();
  const restore = silenceErrors();
  try {
    const outcome = await runStrategy(strategyFor(port), makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'fail');
    assert.strictEqual(outcome.status, 401);
  } finally {
    restore();
  }
});

test('the strategy inherits SAML 1.1 support from the core', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const strategy = strategyFor(server.port, { cas_version: 'saml1.1' });
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-saml', query: { ticket: 'ST-saml' },
    }));
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(outcome.user.user, 'samluser');
    assert.deepStrictEqual(outcome.user.attributes.memberOf, ['staff', 'faculty']);
    assert.strictEqual(server.requests[0].method, 'POST');
  } finally {
    await server.close();
  }
});

test('the strategy inherits CAS 1.0 support from the core', async () => {
  const server = await startCasServer(() => 'yes\nlegacyuser\n');
  try {
    const strategy = strategyFor(server.port, { cas_version: '1.0' });
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(outcome.user.user, 'legacyuser');
  } finally {
    await server.close();
  }
});

test('gateway authentication redirects once with gateway=true', async () => {
  const strategy = new Strategy({ ...BASE });
  const req = makeReq();
  const outcome = await runStrategy(strategy, req, { gateway: true });
  assert.strictEqual(outcome.type, 'redirect');
  assert.strictEqual(new URL(outcome.location).searchParams.get('gateway'), 'true');
  assert.strictEqual(req.session[FLAG], true);
});

test('gateway passes when CAS returns the client with no ticket', async () => {
  const strategy = new Strategy({ ...BASE });
  const outcome = await runStrategy(strategy, makeReq({ session: { [FLAG]: true } }),
    { gateway: true });
  assert.strictEqual(outcome.type, 'pass');
});

test('gateway works without a session, using the URL marker', async () => {
  const strategy = new Strategy({ ...BASE });
  const first = makeReq();
  delete first.session;
  const redirected = await runStrategy(strategy, first, { gateway: true });
  assert.strictEqual(redirected.type, 'redirect');
  const service = new URL(new URL(redirected.location).searchParams.get('service'));
  assert.strictEqual(service.searchParams.get(MARKER), '1');

  // Following CAS back, still with no session, terminates the check.
  const second = makeReq({ query: { [MARKER]: '1' } });
  delete second.session;
  const passed = await runStrategy(strategy, second, { gateway: true });
  assert.strictEqual(passed.type, 'pass');
});

test('a successful gateway ticket clears the flag', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const req = makeReq({
      url: '/app?ticket=ST-gw', query: { ticket: 'ST-gw' }, session: { [FLAG]: true },
    });
    const outcome = await runStrategy(strategyFor(server.port), req, { gateway: true });
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(req.session[FLAG], undefined);
  } finally {
    await server.close();
  }
});

test('the strategy works without any session at all when a ticket is present', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const req = makeReq({ url: '/app?ticket=ST-1', query: { ticket: 'ST-1' } });
    delete req.session;
    const outcome = await runStrategy(strategyFor(server.port), req);
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(outcome.user.user, 'casuser');
  } finally {
    await server.close();
  }
});

test('a gateway check passes rather than failing when CAS rejects the ticket', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const outcome = await runStrategy(strategyFor(server.port), makeReq({
      url: `/?${MARKER}=1&ticket=ST-stale`, query: { [MARKER]: '1', ticket: 'ST-stale' },
    }), { gateway: true });
    assert.strictEqual(outcome.type, 'pass');
  } finally {
    restore();
    await server.close();
  }
});

test('a non-gateway authenticate still fails a rejected ticket with 401', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const outcome = await runStrategy(strategyFor(server.port), makeReq({
      url: '/app?ticket=bad', query: { ticket: 'bad' },
    }));
    assert.strictEqual(outcome.type, 'fail');
    assert.strictEqual(outcome.status, 401);
  } finally {
    restore();
    await server.close();
  }
});

test('a gateway redirect and its validation agree on the service URL', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const strategy = strategyFor(server.port);
    const redirected = await runStrategy(strategy, makeReq({ url: '/', path: '/' }),
      { gateway: true });
    const serviceAtLogin = new URL(redirected.location).searchParams.get('service');

    const outcome = await runStrategy(strategy, makeReq({
      url: `/?${MARKER}=1&ticket=ST-gw`, query: { [MARKER]: '1', ticket: 'ST-gw' },
    }), { gateway: true });
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(new URL(server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('service'), serviceAtLogin);
  } finally {
    await server.close();
  }
});

test('the strategy no longer needs its cas_port fixed up by hand', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    // Constructed straight from a cas_url carrying an explicit port.
    const strategy = new Strategy({
      cas_url: `http://127.0.0.1:${server.port}/cas`,
      service_url: 'http://my-service-host.com',
    });
    const outcome = await runStrategy(strategy, makeReq({
      url: '/app?ticket=ST-1', query: { ticket: 'ST-1' },
    }));
    assert.strictEqual(outcome.type, 'success');
    assert.strictEqual(outcome.user.user, 'casuser');
  } finally {
    await server.close();
  }
});
