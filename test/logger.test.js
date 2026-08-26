'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  CASAuthentication, makeReq, makeRes, makeNext, startCasServer, casFor, collectingLogger,
} = require('./helpers.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };

test('console is the logger when none is supplied', () => {
  assert.strictEqual(new CASAuthentication(BASE).logger, console);
});

test('a logger without an error method is refused', () => {
  [{}, { error: 'not a function' }, null, 0].forEach((logger) => {
    assert.throws(() => new CASAuthentication({ ...BASE, logger }),
      /logger to be an object with an error method/,
      `${JSON.stringify(logger)} must be refused`);
  });
});

test('a rejected ticket is reported to the supplied logger, not to console', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const logger = collectingLogger();
  const originalConsoleError = console.error;
  let consoleCalls = 0;
  console.error = () => { consoleCalls += 1; };
  try {
    const cas = casFor(server.port, { logger });
    await new Promise((resolve) => {
      cas._validateTicket({ ticket: 'ST-bad', service: 'http://my-service-host.com/app' }, resolve);
    });
  } finally {
    console.error = originalConsoleError;
    await server.close();
  }
  assert.strictEqual(consoleCalls, 0, 'console.error must not be used once a logger is supplied');
  assert.ok(logger.messages().some((m) => /CAS rejected the ticket/.test(m)),
    `expected a rejection diagnostic, got ${JSON.stringify(logger.messages())}`);
});

test('an unreachable CAS server is reported to the supplied logger', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  const port = server.port;
  await server.close();
  const logger = collectingLogger();
  const cas = casFor(port, { logger });
  await new Promise((resolve) => {
    cas._validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }, resolve);
  });
  assert.ok(logger.messages().some((m) => /Request error with CAS/.test(m)),
    `expected a transport diagnostic, got ${JSON.stringify(logger.messages())}`);
});

test('a success without a username is reported to the supplied logger', async () => {
  const server = await startCasServer(() => fx.cas2SuccessFor('   '));
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { cas_version: '2.0', logger });
    await new Promise((resolve) => {
      cas._validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }, resolve);
    });
  } finally {
    await server.close();
  }
  assert.ok(logger.messages().some((m) => /succeeded without a username/.test(m)),
    `expected a blank-username diagnostic, got ${JSON.stringify(logger.messages())}`);
});

test('a session store that fails to regenerate is reported, and the login continues', async () => {
  const logger = collectingLogger();
  const cas = new CASAuthentication({ ...BASE, logger });
  const session = {
    regenerate(cb) { cb(new Error('store offline')); },
  };
  const req = makeReq({ session });
  await new Promise((resolve) => {
    cas._establishSession(req, 'casuser', {}, resolve);
  });
  assert.strictEqual(req.session.cas_user, 'casuser', 'the login must still complete');
  assert.ok(logger.messages().some((m) => /failed to regenerate the session/.test(m)),
    `expected a regenerate diagnostic, got ${JSON.stringify(logger.messages())}`);
});

test('a session store that fails to destroy is reported on logout', () => {
  const logger = collectingLogger();
  const cas = new CASAuthentication({ ...BASE, destroy_session: true, logger });
  // Supplied up front: makeReq only installs its own destroy() when the session
  // does not already have one, and installs it non-writable.
  const req = makeReq({
    session: { cas_user: 'casuser', destroy: (cb) => cb(new Error('store offline')) },
  });
  cas.logout(req, makeRes(), makeNext());
  assert.ok(logger.messages().some((m) => /failed to destroy the session/.test(m)),
    `expected a destroy diagnostic, got ${JSON.stringify(logger.messages())}`);
});

test('a malformed CAS response is reported to the supplied logger', async () => {
  const server = await startCasServer(() => '<not-xml');
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger });
    await new Promise((resolve) => {
      cas._validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }, resolve);
    });
  } finally {
    await server.close();
  }
  assert.ok(logger.calls.length > 0, 'a malformed response must be reported somewhere');
});
