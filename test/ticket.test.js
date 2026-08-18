'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  makeReq, makeRes, makeNext, startCasServer, casFor, silenceErrors,
} = require('./helpers.js');
const fx = require('./fixtures.js');

test('a valid ticket populates the session and redirects to the saved return URL', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port, { session_info: 'cas_info' });
    const req = makeReq({
      url: '/app?ticket=ST-1234',
      query: { ticket: 'ST-1234' },
      session: { cas_return_to: '/dashboard' },
    });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;

    assert.strictEqual(req.session.cas_user, 'casuser');
    assert.deepStrictEqual(req.session.cas_info, {
      email: 'casuser@example.edu',
      displayname: 'Cas User',
    });
    assert.deepStrictEqual(res.redirects, ['/dashboard']);
  } finally {
    await cas_server.close();
  }
});

test('the validation request targets the versioned endpoint with service and ticket', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port, { cas_version: '3.0' });
    const req = makeReq({ url: '/app?ticket=ST-9', query: { ticket: 'ST-9' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;

    assert.strictEqual(cas_server.requests.length, 1);
    const sent = new URL(cas_server.requests[0].url, 'http://127.0.0.1');
    assert.strictEqual(sent.pathname, '/cas/p3/serviceValidate');
    assert.strictEqual(sent.searchParams.get('ticket'), 'ST-9');
    // The service must match what was sent to /login, query string stripped.
    assert.strictEqual(sent.searchParams.get('service'), 'http://my-service-host.com/app');
    assert.strictEqual(cas_server.requests[0].method, 'GET');
  } finally {
    await cas_server.close();
  }
});

test('CAS 2.0 validates at /serviceValidate rather than the p3 endpoint', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port, { cas_version: '2.0' });
    const req = makeReq({ url: '/app?ticket=ST-2', query: { ticket: 'ST-2' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;
    assert.strictEqual(new URL(cas_server.requests[0].url, 'http://127.0.0.1').pathname,
      '/cas/serviceValidate');
  } finally {
    await cas_server.close();
  }
});

test('CAS 1.0 validates a plaintext response end to end', async () => {
  const cas_server = await startCasServer(() => 'yes\nlegacyuser\n');
  try {
    const cas = casFor(cas_server.port, { cas_version: '1.0' });
    const req = makeReq({ url: '/app?ticket=ST-3', query: { ticket: 'ST-3' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;
    assert.strictEqual(req.session.cas_user, 'legacyuser');
    assert.strictEqual(new URL(cas_server.requests[0].url, 'http://127.0.0.1').pathname,
      '/cas/validate');
  } finally {
    await cas_server.close();
  }
});

test('SAML 1.1 posts a SOAP envelope containing the assertion artifact', async () => {
  const cas_server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(cas_server.port, { cas_version: 'saml1.1', session_info: 'cas_info' });
    const req = makeReq({ url: '/app?ticket=ST-saml', query: { ticket: 'ST-saml' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;

    const sent = cas_server.requests[0];
    assert.strictEqual(sent.method, 'POST');
    assert.strictEqual(sent.headers['content-type'], 'text/xml');
    assert.match(sent.body, /<samlp:AssertionArtifact>\s*ST-saml\s*<\/samlp:AssertionArtifact>/);
    assert.strictEqual(new URL(sent.url, 'http://127.0.0.1').searchParams.get('TARGET'),
      'http://my-service-host.com/app');
    assert.strictEqual(req.session.cas_user, 'samluser');
    assert.deepStrictEqual(req.session.cas_info.memberOf, ['staff', 'faculty']);
  } finally {
    await cas_server.close();
  }
});

test('a rejected ticket produces a 401 and leaves the session unauthenticated', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const cas = casFor(cas_server.port);
    const req = makeReq({ url: '/app?ticket=bad', query: { ticket: 'bad' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;
    assert.deepStrictEqual(res.statuses, [401]);
    assert.strictEqual(req.session.cas_user, undefined);
  } finally {
    restore();
    await cas_server.close();
  }
});

test('an unreachable CAS server produces a 401 rather than hanging', async () => {
  const cas_server = await startCasServer(() => '');
  const { port } = cas_server;
  await cas_server.close();
  const restore = silenceErrors();
  try {
    const cas = casFor(port);
    const req = makeReq({ url: '/app?ticket=ST-x', query: { ticket: 'ST-x' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;
    assert.deepStrictEqual(res.statuses, [401]);
  } finally {
    restore();
  }
});

test('session_info is left alone when not configured', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const req = makeReq({ url: '/app?ticket=ST-4', query: { ticket: 'ST-4' }, session: { cas_return_to: '/app' } });
    const res = makeRes();
    cas.bounce(req, res, makeNext());
    await res.settled;
    assert.strictEqual(req.session.cas_user, 'casuser');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(req.session, 'false'), false);
  } finally {
    await cas_server.close();
  }
});

test('block ignores a ticket in the query string and still 401s', async () => {
  const cas_server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(cas_server.port);
    const res = makeRes();
    cas.block(makeReq({ url: '/api?ticket=ST-5', query: { ticket: 'ST-5' } }), res, makeNext());
    assert.deepStrictEqual(res.statuses, [401]);
    assert.strictEqual(cas_server.requests.length, 0);
  } finally {
    await cas_server.close();
  }
});
