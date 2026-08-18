'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { CASAuthentication, makeReq, makeRes, makeNext } = require('./helpers.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });

test('an authenticated session passes straight through bounce', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' } });
  const res = makeRes();
  const next = makeNext();
  cas.bounce(req, res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(res.redirects, []);
});

test('an authenticated session passes straight through block', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' } });
  const res = makeRes();
  const next = makeNext();
  cas.block(req, res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(res.statuses, []);
});

test('a custom session_name is what gets checked', () => {
  const cas = casOf({ session_name: 'netid' });
  const req = makeReq({ session: { netid: 'abc123' } });
  const next = makeNext();
  cas.block(req, makeRes(), next);
  assert.strictEqual(next.calls.length, 1);
});

test('block returns 401 for an unauthenticated client without redirecting', () => {
  const cas = casOf();
  const res = makeRes();
  const next = makeNext();
  cas.block(makeReq(), res, next);
  assert.deepStrictEqual(res.statuses, [401]);
  assert.deepStrictEqual(res.redirects, []);
  assert.strictEqual(next.calls.length, 0);
});

test('bounce redirects an unauthenticated client to the CAS login', () => {
  const cas = casOf();
  const res = makeRes();
  cas.bounce(makeReq({ url: '/app', path: '/app' }), res, makeNext());
  assert.strictEqual(res.redirects.length, 1);
  const target = new URL(res.redirects[0]);
  assert.strictEqual(target.origin + target.pathname, 'https://cas.example.edu/cas/login');
  assert.strictEqual(target.searchParams.get('service'), 'https://app.example.edu/app');
});

test('bounce_redirect sends an authenticated client to its returnTo parameter', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' }, query: { returnTo: '/dashboard' } });
  const res = makeRes();
  const next = makeNext();
  cas.bounce_redirect(req, res, next);
  assert.deepStrictEqual(res.redirects, ['/dashboard']);
  assert.strictEqual(req.session.cas_return_to, '/dashboard');
  assert.strictEqual(next.calls.length, 0);
});

test('bounce_redirect falls back to the request path when returnTo is absent', () => {
  const cas = casOf();
  const req = makeReq({ session: { cas_user: 'casuser' }, url: '/app?x=1' });
  const res = makeRes();
  cas.bounce_redirect(req, res, makeNext());
  assert.deepStrictEqual(res.redirects, ['/app?x=1']);
});

test('login carries renew through to the CAS login URL when enabled', () => {
  const res = makeRes();
  casOf({ renew: true }).login(makeReq(), res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('renew'), 'true');
});

test('login omits renew by default', () => {
  const res = makeRes();
  casOf().login(makeReq(), res, makeNext());
  assert.strictEqual(new URL(res.redirects[0]).searchParams.has('renew'), false);
});

test('login prefers an explicit returnTo over the request path', () => {
  const req = makeReq({ query: { returnTo: '/deep/link' } });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/deep/link');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/deep/link');
});

test('login falls back to / when the request carries no usable path', () => {
  const req = makeReq({ path: undefined, url: undefined, originalUrl: undefined });
  casOf().login(req, makeRes(), makeNext());
  assert.strictEqual(req.session.cas_return_to, '/');
});

test('the service URL keeps a router mount prefix', () => {
  // Inside app.use('/portal', router) both req.url and req.path are relative to
  // the mount point; only originalUrl has the prefix CAS must return to.
  const req = makeReq({ originalUrl: '/portal/page', url: '/page', path: '/page' });
  const res = makeRes();
  casOf().bounce(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/portal/page');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/portal/page');
});

test('dev mode authenticates as the configured user without contacting CAS', () => {
  const cas = casOf({ is_dev_mode: true, dev_mode_user: 'devuser', session_info: 'cas_info', dev_mode_info: { email: 'dev@example.edu' } });
  const req = makeReq();
  const res = makeRes();
  const next = makeNext();
  cas.bounce(req, res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.strictEqual(req.session.cas_user, 'devuser');
  assert.deepStrictEqual(req.session.cas_info, { email: 'dev@example.edu' });
  assert.deepStrictEqual(res.redirects, []);
});

test('dev mode also short-circuits block, which would otherwise 401', () => {
  const cas = casOf({ is_dev_mode: true, dev_mode_user: 'devuser' });
  const res = makeRes();
  const next = makeNext();
  cas.block(makeReq(), res, next);
  assert.strictEqual(next.calls.length, 1);
  assert.deepStrictEqual(res.statuses, []);
});

test('dev mode does not create a session key named "false" when session_info is unset', () => {
  const cas = casOf({ is_dev_mode: true, dev_mode_user: 'devuser' });
  const req = makeReq();
  cas.bounce(req, makeRes(), makeNext());
  assert.strictEqual(Object.prototype.hasOwnProperty.call(req.session, 'false'), false);
  assert.deepStrictEqual(Object.keys(req.session).sort(), ['cas_user', 'userType']);
});

test('dev mode stores dev_mode_info only under a configured session_info', () => {
  const cas = casOf({
    is_dev_mode: true, dev_mode_user: 'devuser', session_info: 'cas_info',
    dev_mode_info: { email: 'dev@example.edu' },
  });
  const req = makeReq();
  cas.bounce(req, makeRes(), makeNext());
  assert.deepStrictEqual(req.session.cas_info, { email: 'dev@example.edu' });
  assert.strictEqual(Object.prototype.hasOwnProperty.call(req.session, 'false'), false);
});

test('userType is initialised to an empty string on the unauthenticated path', () => {
  const cas = casOf();
  const req = makeReq();
  cas.bounce(req, makeRes(), makeNext());
  assert.strictEqual(req.session.userType, '');
});

test('logout deletes just the CAS session variables by default', () => {
  const cas = casOf({ session_info: 'cas_info' });
  const req = makeReq({ session: { cas_user: 'casuser', cas_info: { a: 1 }, other: 'keep' } });
  const res = makeRes();
  cas.logout(req, res, makeNext());
  assert.strictEqual(req.session.cas_user, undefined);
  assert.strictEqual(req.session.cas_info, undefined);
  assert.strictEqual(req.session.other, 'keep');
  assert.deepStrictEqual(res.redirects, ['https://cas.example.edu/cas/logout']);
});

test('logout destroys the whole session when destroy_session is set', () => {
  const cas = casOf({ destroy_session: true });
  const req = makeReq({ session: { cas_user: 'casuser', other: 'gone' } });
  const res = makeRes();
  cas.logout(req, res, makeNext());
  assert.strictEqual(req.sessionDestroyed, true);
  // express-session removes req.session on destroy, so nothing may touch it
  // after this point.
  assert.strictEqual(req.session, undefined);
  assert.deepStrictEqual(res.redirects, ['https://cas.example.edu/cas/logout']);
});

test('logout still redirects when session.destroy reports an error', () => {
  const cas = casOf({ destroy_session: true });
  const req = makeReq();
  Object.defineProperty(req.session, 'destroy', {
    value: (cb) => { delete req.session; cb(new Error('store offline')); },
  });
  const res = makeRes();
  const originalError = console.error;
  console.error = () => {};
  cas.logout(req, res, makeNext());
  console.error = originalError;
  assert.deepStrictEqual(res.redirects, ['https://cas.example.edu/cas/logout']);
});

test('an empty returnTo falls back to the request path', () => {
  // A bare `?returnTo=` must not produce an empty service URL or a redirect to
  // nothing.
  const req = makeReq({ query: { returnTo: '' }, path: '/app' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/app');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/app');
});

test('a repeated returnTo falls back to the request path', () => {
  // Express yields an array here, which is not a usable path.
  const req = makeReq({ query: { returnTo: ['/a', '/b'] }, path: '/app' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/app');
});

test('a bracketed returnTo falls back to the request path', () => {
  // Express's extended query parser yields an object here.
  const req = makeReq({ query: { returnTo: { x: '1' } }, path: '/app' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/app');
});

test('a returnTo that cannot be encoded falls back rather than throwing', () => {
  // encodeURI rejects lone surrogates.
  const req = makeReq({ query: { returnTo: 'a\uD800b' }, path: '/app' });
  const res = makeRes();
  const originalError = console.error;
  console.error = () => {};
  assert.doesNotThrow(() => casOf().login(req, res, makeNext()));
  console.error = originalError;
  assert.strictEqual(req.session.cas_return_to, '/app');
});

test('a returnTo needing encoding is normalised to wire form', () => {
  const req = makeReq({ query: { returnTo: '/my reports' }, path: '/app' });
  const res = makeRes();
  casOf().login(req, res, makeNext());
  assert.strictEqual(req.session.cas_return_to, '/my%20reports');
  assert.strictEqual(new URL(res.redirects[0]).searchParams.get('service'),
    'https://app.example.edu/my%20reports');
});

test('the page query string is not sent to CAS', () => {
  const req = makeReq({ url: '/reset?token=s3cret', path: '/reset' });
  const res = makeRes();
  casOf().bounce(req, res, makeNext());
  const service = new URL(res.redirects[0]).searchParams.get('service');
  assert.strictEqual(service, 'https://app.example.edu/reset');
  assert.ok(!service.includes('s3cret'), 'page parameters must not reach the CAS server');
});
