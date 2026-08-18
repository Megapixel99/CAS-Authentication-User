'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const express = require('express');
const session = require('express-session');
const { CASAuthentication, startCasServer } = require('./helpers.js');
const fx = require('./fixtures.js');

/**
 * These tests run against real express-session rather than a double. That
 * matters: express-session's destroy() removes req.session outright, and a
 * hand-written double that only sets a flag hides anything that touches the
 * session afterwards.
 */

/** GET that does not follow redirects and threads cookies back. */
function get(port, path, cookie) {
  return new Promise((resolve, reject) => {
    const headers = cookie ? { Cookie: cookie } : {};
    http.get({ host: '127.0.0.1', port, path, headers }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({
        status: res.statusCode,
        location: res.headers.location,
        cookie: (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ') || cookie,
        body,
      }));
    }).on('error', reject);
  });
}

async function mount(build, casOptions) {
  const cas = new CASAuthentication({
    cas_url: 'https://cas.example.edu/cas',
    service_url: 'http://my-service-host.com',
    ...casOptions,
  });
  const app = express();
  app.set('env', 'test');
  app.use(session({ secret: 'test secret', resave: false, saveUninitialized: true }));
  build(app, cas);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return { cas, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

test('logout redirects rather than throwing when destroy_session is set', async () => {
  // Regression guard: a delete on req.session placed after destroy() threw
  // TypeError here and turned every logout into a 500.
  const app = await mount((a, cas) => {
    a.get('/seed', (req, res) => { req.session.cas_user = 'casuser'; res.send('ok'); });
    a.get('/logout', cas.logout);
  }, { destroy_session: true });
  try {
    const seeded = await get(app.port, '/seed');
    const res = await get(app.port, '/logout', seeded.cookie);
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.location, 'https://cas.example.edu/cas/logout');
  } finally {
    await app.close();
  }
});

test('logout redirects and clears just the CAS keys when destroy_session is not set', async () => {
  const app = await mount((a, cas) => {
    a.get('/seed', (req, res) => {
      req.session.cas_user = 'casuser';
      req.session.cas_info = { email: 'casuser@example.edu' };
      req.session.mine = 'keep';
      res.send('ok');
    });
    a.get('/logout', cas.logout);
    a.get('/peek', (req, res) => res.json({
      cas_user: req.session.cas_user || null,
      cas_info: req.session.cas_info || null,
      mine: req.session.mine || null,
    }));
  }, { session_info: 'cas_info' });
  try {
    const seeded = await get(app.port, '/seed');
    const out = await get(app.port, '/logout', seeded.cookie);
    assert.strictEqual(out.status, 302);
    const peek = JSON.parse((await get(app.port, '/peek', seeded.cookie)).body);
    assert.deepStrictEqual(peek, { cas_user: null, cas_info: null, mine: 'keep' });
  } finally {
    await app.close();
  }
});

test('logout after a destroying logout still redirects', async () => {
  // Two logouts in a row: the second runs with a session that was already
  // destroyed and re-created by the middleware.
  const app = await mount((a, cas) => {
    a.get('/logout', cas.logout);
  }, { destroy_session: true });
  try {
    const first = await get(app.port, '/logout');
    const second = await get(app.port, '/logout', first.cookie);
    assert.strictEqual(first.status, 302);
    assert.strictEqual(second.status, 302);
  } finally {
    await app.close();
  }
});

test('a gateway check over real sessions redirects once and then passes through', async () => {
  const app = await mount((a, cas) => {
    a.use(cas.gateway, (req, res) => res.json({ user: req.session[cas.session_name] || null }));
  });
  try {
    const first = await get(app.port, '/');
    assert.strictEqual(first.status, 302);
    const service = new URL(new URL(first.location).searchParams.get('service'));
    assert.strictEqual(service.searchParams.get(CASAuthentication.GATEWAY_QUERY_PARAM), '1');

    // CAS returns the client to that service with no ticket, cookie intact.
    const second = await get(app.port, `${service.pathname}${service.search}`, first.cookie);
    assert.strictEqual(second.status, 200);
    assert.deepStrictEqual(JSON.parse(second.body), { user: null });

    // And a later, unmarked request must not bounce again - the session holds
    // the flag now.
    const third = await get(app.port, '/', first.cookie);
    assert.strictEqual(third.status, 200);
  } finally {
    await app.close();
  }
});

test('logging out re-arms a gateway check over real sessions', async () => {
  const app = await mount((a, cas) => {
    a.get('/logout', cas.logout);
    a.use(cas.gateway, (req, res) => res.json({ user: req.session[cas.session_name] || null }));
  });
  try {
    const first = await get(app.port, '/');
    const marked = new URL(new URL(first.location).searchParams.get('service'));
    const passed = await get(app.port, `${marked.pathname}${marked.search}`, first.cookie);
    assert.strictEqual(passed.status, 200);

    await get(app.port, '/logout', first.cookie);
    const after = await get(app.port, '/', first.cookie);
    assert.strictEqual(after.status, 302, 'logout should allow a fresh gateway check');
  } finally {
    await app.close();
  }
});

test('a returnTo needing percent-encoding still validates', async () => {
  // The service sent to /login and the service sent for validation have to match
  // byte for byte or CAS rejects the ticket.
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mount((a, cas) => {
    a.get('/authenticate', cas.login);
    a.use((req, res, next) => {
      if (req.query.ticket) { cas.bounce(req, res, next); return; }
      next();
    }, (req, res) => res.json({ user: req.session[cas.session_name] || null }));
  }, { cas_url: `http://127.0.0.1:${cas_server.port}/cas` });
  try {
    const login = await get(app.port, '/authenticate?returnTo=%2Fmy%20reports');
    const serviceAtLogin = new URL(login.location).searchParams.get('service');
    assert.strictEqual(serviceAtLogin, 'http://my-service-host.com/my%20reports');

    // CAS sends the browser to that service with a ticket appended.
    const back = await get(app.port, '/my%20reports?ticket=ST-1', login.cookie);
    const serviceAtValidation = new URL(cas_server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('service');
    assert.strictEqual(serviceAtValidation, serviceAtLogin);
    // Matching service means CAS accepted it, so this is a redirect, not a 401.
    assert.strictEqual(back.status, 302);
    assert.strictEqual(back.location, '/my%20reports');
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('a plain path with no returnTo still validates', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  const app = await mount((a, cas) => {
    a.use((req, res, next) => {
      if (req.query.ticket) { cas.bounce(req, res, next); return; }
      cas.bounce(req, res, next);
    }, (req, res) => res.json({ user: req.session[cas.session_name] || null }));
  }, { cas_url: `http://127.0.0.1:${cas_server.port}/cas` });
  try {
    const login = await get(app.port, '/dashboard');
    const serviceAtLogin = new URL(login.location).searchParams.get('service');
    await get(app.port, '/dashboard?ticket=ST-1', login.cookie);
    assert.strictEqual(new URL(cas_server.requests[0].url, 'http://127.0.0.1')
      .searchParams.get('service'), serviceAtLogin);
  } finally {
    await app.close();
    await cas_server.close();
  }
});

test('renew with gateway keeps prompting instead of falling through', async () => {
  // renew takes precedence over gateway, so the route must behave like bounce.
  const app = await mount((a, cas) => {
    a.use(cas.gateway, (req, res) => res.json({ user: null }));
  }, { renew: true });
  try {
    const first = await get(app.port, '/');
    assert.strictEqual(first.status, 302);
    assert.strictEqual(new URL(first.location).searchParams.get('renew'), 'true');
    // The user abandons the CAS login form and comes back.
    const second = await get(app.port, '/', first.cookie);
    assert.strictEqual(second.status, 302, 'renew must not fall through after one visit');
  } finally {
    await app.close();
  }
});
