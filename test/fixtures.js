'use strict';

const CAS2_SUCCESS = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>casuser</cas:user>
    <cas:attributes>
      <cas:email>casuser@example.edu</cas:email>
      <cas:displayName>Cas User</cas:displayName>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>`;

const CAS2_SUCCESS_NO_ATTRS = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>plainuser</cas:user>
  </cas:authenticationSuccess>
</cas:serviceResponse>`;

const CAS2_FAILURE = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">
    Ticket ST-1 not recognized
  </cas:authenticationFailure>
</cas:serviceResponse>`;

// Neither success nor failure - a well-formed but meaningless response.
const CAS2_EMPTY = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
</cas:serviceResponse>`;

// Real CAS puts xsi:type on AttributeValue, which is what makes xml2js expose
// the text as `._` - the shape index.js reads.
const SAML_SUCCESS = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
    <Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol">
      <Status>
        <StatusCode Value="samlp:Success"/>
      </Status>
      <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion">
        <AuthenticationStatement>
          <Subject>
            <NameIdentifier>samluser</NameIdentifier>
          </Subject>
        </AuthenticationStatement>
        <AttributeStatement>
          <Attribute AttributeName="email">
            <AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">samluser@example.edu</AttributeValue>
          </Attribute>
          <Attribute AttributeName="memberOf">
            <AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">staff</AttributeValue>
            <AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">faculty</AttributeValue>
          </Attribute>
        </AttributeStatement>
      </Assertion>
    </Response>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`;

// Same, but AttributeValue carries no XML attributes at all.
const SAML_SUCCESS_BARE_VALUE = SAML_SUCCESS
  .replace(/ xsi:type="xs:string" xmlns:xsi="[^"]*"/g, '');

// A CAS server that releases no attributes omits the AttributeStatement
// entirely. The 2.0/3.0 parser has always coped with the equivalent; the SAML
// one used to reach through it and fail the whole login.
const SAML_SUCCESS_NO_ATTR_STATEMENT = SAML_SUCCESS
  .replace(/ *<AttributeStatement>[\s\S]*<\/AttributeStatement>\n/, '');

// An attribute element carrying no value at all.
const SAML_SUCCESS_VALUELESS_ATTR = SAML_SUCCESS
  .replace(/ *<Attribute AttributeName="email">[\s\S]*?<\/Attribute>/,
    '          <Attribute AttributeName="email"/>');

const SAML_FAILURE = SAML_SUCCESS.replace('samlp:Success', 'samlp:RequestDenied');

// A repeated attribute element, which xml2js surfaces as an array.
const CAS2_REPEATED_ATTRS = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>groupuser</cas:user>
    <cas:attributes>
      <cas:memberOf>staff</cas:memberOf>
      <cas:memberOf>faculty</cas:memberOf>
      <cas:email>groupuser@example.edu</cas:email>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>`;

/** Builds a CAS 2.0/3.0 success response for an arbitrary username. */
function cas2SuccessFor(user) {
  return `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>${user}</cas:user>
  </cas:authenticationSuccess>
</cas:serviceResponse>`;
}

module.exports = {
  CAS2_REPEATED_ATTRS,
  cas2SuccessFor,
  CAS2_SUCCESS,
  CAS2_SUCCESS_NO_ATTRS,
  CAS2_FAILURE,
  CAS2_EMPTY,
  SAML_SUCCESS,
  SAML_SUCCESS_BARE_VALUE,
  SAML_SUCCESS_NO_ATTR_STATEMENT,
  SAML_SUCCESS_VALUELESS_ATTR,
  SAML_FAILURE,
};
