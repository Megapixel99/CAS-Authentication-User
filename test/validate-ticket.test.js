'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { startCasServer, casFor, silenceErrors } = require('./helpers.js');
const fx = require('./fixtures.js');

/** Promisified _validateTicket. */
function validateTicket(cas, params) {
  return new Promise((resolve) => {
    cas._validateTicket(params, (err, user, attributes) => resolve({ err, user, attributes }));
  });
}

test('_validateTicket resolves a username without touching req, res or a session', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const { err, user, attributes } = await validateTicket(casFor(server.port), {
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    assert.strictEqual(err, null);
    assert.strictEqual(user, 'casuser');
    assert.deepStrictEqual(attributes, {
      email: 'casuser@example.edu', displayname: 'Cas User',
    });
  } finally {
    await server.close();
  }
});

test('_validateTicket percent-encodes the ticket and service', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    await validateTicket(casFor(server.port), {
      ticket: 'ST-a+b&c=d/e',
      service: 'http://my-service-host.com/app?x=1&y=2',
    });
    const sent = new URL(server.requests[0].url, 'http://127.0.0.1');
    // Round-tripping through URLSearchParams proves the encoding survived intact.
    assert.strictEqual(sent.searchParams.get('ticket'), 'ST-a+b&c=d/e');
    assert.strictEqual(sent.searchParams.get('service'), 'http://my-service-host.com/app?x=1&y=2');
  } finally {
    await server.close();
  }
});

test('_validateTicket honours a nested cas_path', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_url: `http://127.0.0.1:${server.port}/idp/cas` });
    await validateTicket(cas, { ticket: 'ST-1', service: 'http://my-service-host.com/app' });
    assert.strictEqual(new URL(server.requests[0].url, 'http://127.0.0.1').pathname,
      '/idp/cas/p3/serviceValidate');
  } finally {
    await server.close();
  }
});

test('_validateTicket reports a CAS rejection as an error', async () => {
  const server = await startCasServer(() => fx.CAS2_FAILURE);
  const restore = silenceErrors();
  try {
    const { err, user } = await validateTicket(casFor(server.port), {
      ticket: 'bad', service: 'http://my-service-host.com/app',
    });
    assert.match(err.message, /INVALID_TICKET/);
    assert.strictEqual(user, undefined);
  } finally {
    restore();
    await server.close();
  }
});

test('_validateTicket reports an HTTP error page as an error rather than a user', async () => {
  const server = await startCasServer(() => ({ status: 500, body: '<html><body>oops</body></html>' }));
  const restore = silenceErrors();
  try {
    const { err, user } = await validateTicket(casFor(server.port), {
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    assert.ok(err instanceof Error);
    assert.strictEqual(user, undefined);
  } finally {
    restore();
    await server.close();
  }
});

test('_validateTicket calls back exactly once', async () => {
  const server = await startCasServer(() => fx.CAS2_SUCCESS);
  try {
    const cas = casFor(server.port);
    const calls = [];
    await new Promise((resolve) => {
      cas._validateTicket({ ticket: 'ST-1', service: 'http://my-service-host.com/app' },
        (err, user) => {
          calls.push(user);
          // Give any stray second callback a chance to land.
          setTimeout(resolve, 50);
        });
    });
    assert.deepStrictEqual(calls, ['casuser']);
  } finally {
    await server.close();
  }
});

test('concurrent validations do not cross contaminate', async () => {
  const server = await startCasServer((req) => {
    const ticket = new URL(req.url, 'http://127.0.0.1').searchParams.get('ticket');
    return fx.cas2SuccessFor(`user-for-${ticket}`);
  });
  try {
    const cas = casFor(server.port);
    const results = await Promise.all(['ST-a', 'ST-b', 'ST-c', 'ST-d'].map((ticket) => validateTicket(cas, {
      ticket, service: 'http://my-service-host.com/app',
    })));
    assert.deepStrictEqual(results.map((r) => r.user),
      ['user-for-ST-a', 'user-for-ST-b', 'user-for-ST-c', 'user-for-ST-d']);
    assert.strictEqual(server.requests.length, 4);
  } finally {
    await server.close();
  }
});

test('a repeated CAS attribute arrives as an array', async () => {
  const server = await startCasServer(() => fx.CAS2_REPEATED_ATTRS);
  try {
    const { attributes } = await validateTicket(casFor(server.port), {
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    // Lower-cased keys, because CAS 2.0/3.0 attributes are XML *tags* and
    // tagNameProcessors.normalize is applied to them.
    assert.deepStrictEqual(attributes, {
      memberof: ['staff', 'faculty'],
      email: 'groupuser@example.edu',
    });
  } finally {
    await server.close();
  }
});

test('SAML 1.1 preserves attribute name case where CAS 2.0/3.0 lower-cases it', async () => {
  const cas2 = await startCasServer(() => fx.CAS2_REPEATED_ATTRS);
  const saml = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const viaCas2 = await validateTicket(casFor(cas2.port), {
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    const samlCas = casFor(saml.port, { cas_version: 'saml1.1' });
    const viaSaml = await validateTicket(samlCas, {
      ticket: 'ST-1', service: 'http://my-service-host.com/app',
    });
    // Same logical attribute, different casing, because SAML carries the name
    // in an XML attribute rather than a tag.
    assert.ok('memberof' in viaCas2.attributes);
    assert.ok('memberOf' in viaSaml.attributes);
  } finally {
    await cas2.close();
    await saml.close();
  }
});

test('the SAML request carries the supplied host in its RequestID', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await validateTicket(cas, {
      ticket: 'ST-1', service: 'http://my-service-host.com/app', host: 'chosen-host.example.edu',
    });
    assert.match(server.requests[0].body, /RequestID="_chosen-host\.example\.edu\.\d+"/);
  } finally {
    await server.close();
  }
});

test('the SAML RequestID falls back to the service hostname when no host is given', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await validateTicket(cas, { ticket: 'ST-1', service: 'http://my-service-host.com/app' });
    assert.match(server.requests[0].body, /RequestID="_my-service-host\.com\.\d+"/);
  } finally {
    await server.close();
  }
});

test('the SAML request declares an ISO 8601 IssueInstant and a correct Content-Length', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await validateTicket(cas, { ticket: 'ST-1', service: 'http://my-service-host.com/app' });
    const request = server.requests[0];
    const instant = request.body.match(/IssueInstant="([^"]+)"/)[1];
    assert.match(instant, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.strictEqual(Number(request.headers['content-length']),
      Buffer.byteLength(request.body));
  } finally {
    await server.close();
  }
});

test('the SAML validation request sends an empty ticket query parameter', async () => {
  const server = await startCasServer(() => fx.SAML_SUCCESS);
  try {
    const cas = casFor(server.port, { cas_version: 'saml1.1' });
    await validateTicket(cas, { ticket: 'ST-1', service: 'http://my-service-host.com/app' });
    const sent = new URL(server.requests[0].url, 'http://127.0.0.1');
    // The artifact travels in the SOAP body; the query parameter stays empty.
    assert.strictEqual(sent.searchParams.get('ticket'), '');
    assert.strictEqual(sent.searchParams.get('TARGET'), 'http://my-service-host.com/app');
  } finally {
    await server.close();
  }
});
