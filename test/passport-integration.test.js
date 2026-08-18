'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const express = require('express');
const passport = require('passport');
const Strategy = require('../strategy.js');
const { CASAuthentication, startCasServer, silenceErrors } = require('./helpers.js');
const fx = require('./fixtures.js');

/** Plain GET that does not follow redirects, so 302s can be asserted on. */
function get(port, path) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
}

/**
 * Mounts a real Express app with a real Passport instance using our strategy,
 * pointed at a fake CAS server.
 */
async function mountApp(casPort, { verify, strategyOptions } = {}) {
  const cas = new CASAuthentication({
    cas_url: `http://127.0.0.1:${casPort}/cas`,
    service_url: 'http://my-service-host.com',
    ...strategyOptions,
  });

  // An isolated Passport instance, so registered strategies cannot leak
  // between tests.
  const pass = new passport.Passport();
  pass.use(new Strategy({ cas, ...strategyOptions }, verify));

  const app = express();
  // Keeps Express's default error handler from printing deliberate 500s.
  app.set('env', 'test');
  app.use(pass.initialize());
  app.get('/app',
    pass.authenticate('cas', { session: false }),
    (req, res) => res.json({ user: req.user }));

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return {
    port: server.address().port,
    close: () => new Promise((r) => server.close(r)),
  };
}

test('passport redirects an unauthenticated request to the CAS login', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mountApp(cas_server.port);
  try {
    const res = await get(app.port, '/app');
    assert.strictEqual(res.status, 302);
    const target = new URL(res.headers.location);
    assert.strictEqual(target.pathname, '/cas/login');
    assert.strictEqual(target.searchParams.get('service'), 'http://my-service-host.com/app');
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('passport authenticates a valid ticket and populates req.user', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mountApp(cas_server.port);
  try {
    const res = await get(app.port, '/app?ticket=ST-valid');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(JSON.parse(res.body), {
      user: {
        provider: 'cas',
        id: 'casuser',
        user: 'casuser',
        attributes: { email: 'casuser@example.edu', displayname: 'Cas User' },
      },
    });
    // The ticket really did go to the CAS server.
    assert.strictEqual(cas_server.requests.length, 1);
    assert.strictEqual(new URL(cas_server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('ticket'), 'ST-valid');
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('passport maps the CAS profile through a verify callback', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mountApp(cas_server.port, {
    verify: (profile, done) => done(null, { netid: profile.user, role: 'staff' }),
  });
  try {
    const res = await get(app.port, '/app?ticket=ST-valid');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(JSON.parse(res.body), { user: { netid: 'casuser', role: 'staff' } });
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('passport returns 401 when CAS rejects the ticket', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_FAILURE);
  const app = await mountApp(cas_server.port);
  const restore = silenceErrors();
  try {
    const res = await get(app.port, '/app?ticket=bad');
    assert.strictEqual(res.status, 401);
  } finally {
    restore();
    await app.close();
    await cas_server.close();
  }
});

test('passport returns 401 when the verify callback declines the user', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mountApp(cas_server.port, {
    verify: (profile, done) => done(null, false, { message: 'not enrolled' }),
  });
  try {
    const res = await get(app.port, '/app?ticket=ST-valid');
    assert.strictEqual(res.status, 401);
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('passport surfaces a verify error as a 500', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mountApp(cas_server.port, {
    verify: (profile, done) => done(new Error('directory unavailable')),
  });
  const restore = silenceErrors();
  try {
    const res = await get(app.port, '/app?ticket=ST-valid');
    assert.strictEqual(res.status, 500);
  } finally {
    restore();
    await app.close();
    await cas_server.close();
  }
});

test('a custom strategy name is what passport registers', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const cas = new CASAuthentication({
    cas_url: `http://127.0.0.1:${cas_server.port}/cas`,
    service_url: 'http://my-service-host.com',
  });
  const pass = new passport.Passport();
  pass.use(new Strategy({ cas, name: 'university' }));

  const app = express();
  app.use(pass.initialize());
  app.get('/app', pass.authenticate('university', { session: false }),
    (req, res) => res.json({ user: req.user.user }));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const res = await get(server.address().port, '/app?ticket=ST-valid');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(JSON.parse(res.body), { user: 'casuser' });
  } finally {
    await new Promise((r) => server.close(r));
    await cas_server.close();
  }
});

test('passport authenticates through the SAML 1.1 protocol', async () => {
  const cas_server = await startCasServer(() => fx.SAML_SUCCESS);
  const app = await mountApp(cas_server.port, { strategyOptions: { cas_version: 'saml1.1' } });
  try {
    const res = await get(app.port, '/app?ticket=ST-saml');
    assert.strictEqual(res.status, 200);
    const { user } = JSON.parse(res.body);
    assert.strictEqual(user.user, 'samluser');
    assert.deepStrictEqual(user.attributes.memberOf, ['staff', 'faculty']);
    assert.strictEqual(cas_server.requests[0].method, 'POST');
  } finally {
    await app.close();
    await cas_server.close();
  }
});
