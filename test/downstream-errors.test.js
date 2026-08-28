'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  makeReq, makeRes, makeNext, startCasServer, casFor, silenceErrors, collectingLogger,
} = require('./helpers.js');
const fx = require('./fixtures.js');

/**
 * The response parsers ran the callback inside their own try/catch, so the try
 * was not guarding the parse: it was guarding everything the application does
 * after a successful login. An exception from the session store, from
 * res.redirect or from a Passport verify callback was caught there, reported as
 * an unreadable CAS response, and dropped by the double-callback guard, leaving
 * a request with no response and no log line naming the cause. On CAS 1.0, which
 * has no try/catch, the same throw took the process with it.
 */
['1.0', '2.0', '3.0', 'saml1.1'].forEach((version) => {
  const body = {
    '1.0': 'yes\ncasuser\n',
    '2.0': fx.CAS2_SUCCESS,
    '3.0': fx.CAS2_SUCCESS,
    'saml1.1': fx.SAML_SUCCESS,
  }[version];

  test(`CAS ${version}: a throwing res.redirect reaches next() instead of hanging`, async () => {
    const server = await startCasServer(() => body);
    const restore = silenceErrors();
    try {
      const cas = casFor(server.port, { cas_version: version });
      const res = makeRes();
      res.redirect = () => { throw new Error('headers already sent'); };
      const next = makeNext();
      cas.bounce(makeReq({
        session: {}, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
      }), res, next);
      await next.settled;
      assert.strictEqual(next.calls.length, 1);
      assert.match(next.calls[0].message, /headers already sent/);
    } finally {
      restore();
      await server.close();
    }
  });

  test(`CAS ${version}: a session destroyed mid-validation is reported, not swallowed`, async () => {
    let req;
    // Another request logs this session out while the CAS round trip is in
    // flight, so the session is there when the middleware checks for it and gone
    // when the answer comes back.
    const server = await startCasServer(() => {
      delete req.session;
      return body;
    });
    const logger = collectingLogger();
    try {
      const cas = casFor(server.port, { cas_version: version, logger });
      req = makeReq({
        session: {}, url: '/app?ticket=ST-1', path: '/app', query: { ticket: 'ST-1' },
      });
      const res = makeRes();
      const next = makeNext();
      cas.bounce(req, res, next);
      await next.settled;
      assert.strictEqual(next.calls.length, 1);
      assert.match(next.calls[0].message, /session was destroyed/);
    } finally {
      await server.close();
    }
  });
});

test('a CAS server answering with an error status says so, rather than blaming the ticket', async () => {
  const server = await startCasServer(() => ({ status: 502, body: '<html>Bad Gateway</html>' }));
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger });
    await assert.rejects(
      cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }),
      /HTTP 502/,
    );
    assert.ok(logger.messages().some((m) => /HTTP 502/.test(m)),
      `expected the status in the diagnostic, got ${JSON.stringify(logger.messages())}`);
    assert.ok(!logger.messages().some((m) => /CAS rejected the ticket/.test(m)),
      'an outage must not be logged as CAS rejecting the ticket');
  } finally {
    await server.close();
  }
});

test('an unreadable response is logged as unreadable, not as a rejection', async () => {
  const server = await startCasServer(() => 'this is not xml at all');
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger });
    await assert.rejects(
      cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }),
    );
    assert.ok(logger.messages().some((m) => /could not be read/.test(m)),
      `expected an unreadable-response diagnostic, got ${JSON.stringify(logger.messages())}`);
  } finally {
    await server.close();
  }
});

test('a response larger than max_response_bytes is refused rather than buffered', async () => {
  const server = await startCasServer(() => 'x'.repeat(200000));
  const logger = collectingLogger();
  try {
    const cas = casFor(server.port, { logger, max_response_bytes: 1024 });
    await assert.rejects(
      cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }),
      /max_response_bytes/,
    );
  } finally {
    await server.close();
  }
});

/**
 * timeout was a socket-inactivity timer, so a server sending a byte every so
 * often reset it indefinitely and the budget never applied.
 */
test('timeout is a deadline, not an inactivity timer', async () => {
  const dribbler = require('http').createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/xml' });
    const tick = setInterval(() => res.write('.'), 20);
    res.on('close', () => clearInterval(tick));
  });
  await new Promise((resolve) => dribbler.listen(0, '127.0.0.1', resolve));
  const restore = silenceErrors();
  const started = Date.now();
  try {
    const cas = casFor(dribbler.address().port, { timeout: 300 });
    await assert.rejects(
      cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }),
      /timed out after 300ms/,
    );
    assert.ok(Date.now() - started < 3000,
      'a dribbling CAS server must not hold the request past the timeout');
  } finally {
    restore();
    await new Promise((resolve) => dribbler.close(resolve));
  }
});

test('a username that arrives as an element with attributes is read, not stringified', async () => {
  // xml2js represents <cas:user format="upn">casuser</cas:user> as an object, and
  // `String(user)` made that `[object Object]` in the session, while both .d.ts
  // files promise a string.
  const server = await startCasServer(() => `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user format="upn">casuser</cas:user>
  </cas:authenticationSuccess>
</cas:serviceResponse>`);
  try {
    const cas = casFor(server.port);
    const { user } = await cas.validateTicket({
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    assert.strictEqual(user, 'casuser');
  } finally {
    await server.close();
  }
});

test('a username that is not text at all is refused', async () => {
  const server = await startCasServer(() => `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user><nested>casuser</nested></cas:user>
  </cas:authenticationSuccess>
</cas:serviceResponse>`);
  const restore = silenceErrors();
  try {
    const cas = casFor(server.port);
    await assert.rejects(
      cas.validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' }),
      /without a username/,
    );
  } finally {
    restore();
    await server.close();
  }
});

test('a ticket cannot inject markup into the SAML 1.1 request', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await cas.validateTicket({
      ticket: 'ST-1</samlp:AssertionArtifact><evil/>',
      service: 'http://my-service-host.com/app',
    }).catch(() => {});
    const sent = server.requests[0].body;
    assert.ok(!sent.includes('<evil/>'), `ticket markup reached the CAS server: ${sent}`);
    assert.ok(sent.includes('&lt;/samlp:AssertionArtifact&gt;'),
      `expected the ticket to be escaped, got: ${sent}`);
  } finally {
    await server.close();
  }
});

test('a host header cannot break the SAML 1.1 RequestID attribute', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await cas.validateTicket({
      ticket: 'ST-1',
      service: 'http://my-service-host.com/app',
      host: 'host" Injected="1',
    }).catch(() => {});
    const sent = server.requests[0].body;
    assert.ok(!/ Injected="1"/.test(sent), `host header broke out of the attribute: ${sent}`);
  } finally {
    await server.close();
  }
});
