'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { CASAuthentication, silenceErrors } = require('./helpers.js');
const fx = require('./fixtures.js');

const BASE = { cas_url: 'https://cas.example.edu/cas', service_url: 'https://app.example.edu' };
const casOf = (version) => new CASAuthentication({ ...BASE, cas_version: version });

/** Promisified _validate, so the callback style reads linearly in tests. */
function validate(cas, body) {
  return new Promise((resolve) => {
    cas._validate(body, (err, user, attributes) => resolve({ err, user, attributes }));
  });
}

test('CAS 1.0 accepts a "yes" response and returns the username', async () => {
  const { err, user } = await validate(casOf('1.0'), 'yes\ncasuser\n');
  assert.strictEqual(err, null);
  assert.strictEqual(user, 'casuser');
});

test('CAS 1.0 rejects a "no" response', async () => {
  const restore = silenceErrors();
  const { err, user } = await validate(casOf('1.0'), 'no\n\n');
  restore();
  assert.match(err.message, /CAS authentication failed/);
  assert.strictEqual(user, undefined);
});

test('CAS 1.0 rejects anything that is neither yes nor no', async () => {
  const { err } = await validate(casOf('1.0'), '<html>gateway timeout</html>');
  assert.match(err.message, /Response from CAS server was bad/);
});

test('CAS 1.0 rejects a bare "yes" with no username line', async () => {
  const { err } = await validate(casOf('1.0'), 'yes');
  assert.match(err.message, /Response from CAS server was bad/);
});

[['2.0', '/serviceValidate'], ['3.0', '/p3/serviceValidate']].forEach(([version]) => {
  test(`CAS ${version} extracts the user and attributes on success`, async () => {
    const { err, user, attributes } = await validate(casOf(version), fx.CAS2_SUCCESS);
    assert.strictEqual(err, null);
    assert.strictEqual(user, 'casuser');
    // Note the lowercasing: tagNameProcessors.normalize is applied to every
    // tag, so a CAS `displayName` attribute reaches the session as `displayname`.
    assert.deepStrictEqual(attributes, {
      email: 'casuser@example.edu',
      displayname: 'Cas User',
    });
  });

  test(`CAS ${version} succeeds with no attributes block`, async () => {
    const { err, user, attributes } = await validate(casOf(version), fx.CAS2_SUCCESS_NO_ATTRS);
    assert.strictEqual(err, null);
    assert.strictEqual(user, 'plainuser');
    assert.strictEqual(attributes, undefined);
  });

  test(`CAS ${version} surfaces the CAS failure code`, async () => {
    const { err } = await validate(casOf(version), fx.CAS2_FAILURE);
    assert.match(err.message, /CAS authentication failed \(INVALID_TICKET\)/);
  });

  test(`CAS ${version} rejects malformed XML`, async () => {
    const { err } = await validate(casOf(version), '<cas:serviceResponse><oops>');
    assert.match(err.message, /Response from CAS server was bad/);
  });

  test(`CAS ${version} rejects a response with neither success nor failure`, async () => {
    const restore = silenceErrors();
    const { err } = await validate(casOf(version), fx.CAS2_EMPTY);
    restore();
    assert.match(err.message, /CAS authentication failed/);
  });
});

test('SAML 1.1 extracts the name identifier and flattens attributes', async () => {
  const { err, user, attributes } = await validate(casOf('saml1.1'), fx.SAML_SUCCESS);
  assert.strictEqual(err, null);
  assert.strictEqual(user, 'samluser');
  assert.deepStrictEqual(attributes, {
    email: 'samluser@example.edu',
    memberOf: ['staff', 'faculty'],
  });
});

test('SAML 1.1 surfaces a non-Success status code', async () => {
  const { err } = await validate(casOf('saml1.1'), fx.SAML_FAILURE);
  assert.match(err.message, /CAS authentication failed \(RequestDenied\)/);
});

test('SAML 1.1 rejects malformed XML', async () => {
  const { err } = await validate(casOf('saml1.1'), 'not xml at all <');
  assert.match(err.message, /Response from CAS server was bad/);
});

test('SAML 1.1 rejects a SOAP envelope with no Response body', async () => {
  const restore = silenceErrors();
  const { err } = await validate(casOf('saml1.1'),
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    + '<SOAP-ENV:Body/></SOAP-ENV:Envelope>');
  restore();
  assert.match(err.message, /CAS authentication failed/);
});

test('SAML 1.1 attribute values without an xsi:type come back undefined', async () => {
  // Documents current behaviour. index.js reads `attributevalue._`, which xml2js
  // only populates when the element carries XML attributes. Real CAS servers send
  // xsi:type, so this is a latent edge rather than a live break.
  const { err, user, attributes } = await validate(casOf('saml1.1'), fx.SAML_SUCCESS_BARE_VALUE);
  assert.strictEqual(err, null);
  assert.strictEqual(user, 'samluser');
  assert.deepStrictEqual(attributes, { email: undefined, memberOf: [undefined, undefined] });
});
