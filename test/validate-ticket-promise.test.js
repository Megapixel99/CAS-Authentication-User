'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { startCasServer, casFor, collectingLogger } = require('./helpers.js');
const fx = require('./fixtures.js');

const SERVICE = 'http://my-service-host.com/app';

/**
 * A server that accepts the connection and never answers, so only the timeout
 * can end the request. Same shape as the one in robustness.test.js.
 */
function startSilentServer() {
  const server = http.createServer(() => {});
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => server.close(r)),
    }));
  });
}

test('validateTicket resolves with the user and attributes', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const { user, attributes } = await casFor(server.port).validateTicket({
      ticket: 'ST-1', service: SERVICE,
    });
    assert.strictEqual(user, 'casuser');
    assert.strictEqual(typeof attributes, 'object');
  } finally {
    await server.close();
  }
});

test('validateTicket resolves attributes as {} when CAS supplies none', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS_NO_ATTRS);
  try {
    const { user, attributes } = await casFor(server.port).validateTicket({
      ticket: 'ST-1', service: SERVICE,
    });
    assert.strictEqual(user, 'plainuser');
    assert.deepStrictEqual(attributes, {},
      'a caller must be able to read an attribute without guarding first');
  } finally {
    await server.close();
  }
});

test('validateTicket rejects rather than resolving with a falsy user', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const logger = collectingLogger();
  try {
    await assert.rejects(
      () => casFor(server.port, { logger }).validateTicket({ ticket: 'ST-bad', service: SERVICE }),
      /CAS authentication failed/,
    );
  } finally {
    await server.close();
  }
});

test('validateTicket rejects when the CAS server cannot be reached', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  const { port } = server;
  await server.close();
  const logger = collectingLogger();
  await assert.rejects(
    () => casFor(port, { logger }).validateTicket({ ticket: 'ST-1', service: SERVICE }),
    (err) => err instanceof Error,
  );
});

test('validateTicket rejects on a timeout', { timeout: 15000 }, async () => {
  const silent = await startSilentServer();
  const logger = collectingLogger();
  try {
    await assert.rejects(
      () => casFor(silent.port, { timeout: 300, logger }).validateTicket({
        ticket: 'ST-1', service: SERVICE,
      }),
      /timed out/,
    );
  } finally {
    await silent.close();
  }
});

test('_validateTicket returns a promise when no callback is given', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const result = casFor(server.port)._validateTicket({ ticket: 'ST-1', service: SERVICE });
    assert.ok(result instanceof Promise, '_validateTicket must return a promise with no callback');
    assert.strictEqual((await result).user, 'casuser');
  } finally {
    await server.close();
  }
});

test('_validateTicket still reports through a callback, and returns nothing', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const outcome = await new Promise((resolve) => {
      const returned = casFor(server.port)._validateTicket(
        { ticket: 'ST-1', service: SERVICE },
        (err, user, attributes) => resolve({ err, user, attributes, returned }),
      );
    });
    assert.strictEqual(outcome.err, null);
    assert.strictEqual(outcome.user, 'casuser');
    assert.strictEqual(outcome.returned, undefined,
      'the callback form must not also return a promise, which would go unhandled on rejection');
  } finally {
    await server.close();
  }
});

test('a non-function callback is refused at the call site', () => {
  assert.throws(
    () => casFor(1).validateTicket && casFor(1)._validateTicket({ ticket: 'x', service: SERVICE }, 'nope'),
    /callback that is not a function/,
  );
});

test('validateTicket is bound, so it survives being passed as a reference', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const { validateTicket } = casFor(server.port);
    const { user } = await validateTicket({ ticket: 'ST-1', service: SERVICE });
    assert.strictEqual(user, 'casuser');
  } finally {
    await server.close();
  }
});
