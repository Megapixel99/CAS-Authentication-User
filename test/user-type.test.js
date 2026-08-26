'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext,
} = require('./helpers.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (options) => new CASAuthentication({ ...BASE, ...options });
const OPTED_OUT = { manage_user_type: false };

test('manage_user_type defaults to true', () => {
  assert.strictEqual(casOf().manage_user_type, true);
  assert.strictEqual(casOf(OPTED_OUT).manage_user_type, false);
});

test('the unauthenticated path leaves userType alone when opted out', () => {
  const req = makeReq();
  casOf(OPTED_OUT).bounce(req, makeRes(), makeNext());
  assert.ok(!('userType' in req.session),
    `the library must not create userType when opted out, got ${JSON.stringify(req.session)}`);
});

test("an application's own userType survives the unauthenticated path when opted out", () => {
  const req = makeReq({ session: { userType: 'guest-trial' } });
  casOf(OPTED_OUT).bounce(req, makeRes(), makeNext());
  assert.strictEqual(req.session.userType, 'guest-trial');
});

test('a gateway redirect leaves userType alone when opted out', () => {
  const req = makeReq({ session: { userType: 'guest-trial' } });
  casOf(OPTED_OUT).gateway(req, makeRes(), makeNext());
  assert.strictEqual(req.session.userType, 'guest-trial');
});

test('dev mode leaves userType alone when opted out', () => {
  const req = makeReq();
  casOf({ ...OPTED_OUT, is_dev_mode: true, dev_mode_user: 'devuser' })
    .bounce(req, makeRes(), makeNext());
  assert.strictEqual(req.session.cas_user, 'devuser');
  assert.ok(!('userType' in req.session), 'dev mode must not create userType when opted out');
});

/**
 * The opt-out hands the field over completely: the application that owns it is
 * the one that clears it. Leaving a stale value behind is exactly the risk the
 * managed default exists to avoid, so this pins that the trade-off is real and
 * documented rather than accidental.
 */
test('logout leaves userType to the application when opted out', () => {
  const req = makeReq({ session: { cas_user: 'alice', userType: 'admin' } });
  casOf(OPTED_OUT).logout(req, makeRes(), makeNext());
  assert.strictEqual(req.session.cas_user, undefined, 'the CAS username is still cleared');
  assert.strictEqual(req.session.userType, 'admin',
    'the application owns the field once it has opted out');
});

test('destroy_session still takes userType with it when opted out', () => {
  const req = makeReq({ session: { cas_user: 'alice', userType: 'admin' } });
  casOf({ ...OPTED_OUT, destroy_session: true }).logout(req, makeRes(), makeNext());
  assert.strictEqual(req.sessionDestroyed, true);
});

test('the managed default is unchanged', () => {
  const req = makeReq({ session: { cas_user: 'alice', userType: 'admin' } });
  casOf().logout(req, makeRes(), makeNext());
  assert.strictEqual(req.session.userType, undefined, 'the default still clears userType');

  const fresh = makeReq();
  casOf().bounce(fresh, makeRes(), makeNext());
  assert.strictEqual(fresh.session.userType, '', 'the default still initialises userType');
});

test('the session key is exported so an application can clear it itself', () => {
  assert.strictEqual(CASAuthentication.USER_TYPE_SESSION_KEY, 'userType');
});
