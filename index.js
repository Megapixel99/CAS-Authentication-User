const url = require('url');
const http = require('http');
const https = require('https');
const parseXML = require('xml2js').parseString;
const XMLprocessors = require('xml2js/lib/processors');

/**
 * The CAS authentication types.
 * @enum {number}
 */
const AUTH_TYPE = {
  BOUNCE: 0,
  BOUNCE_REDIRECT: 1,
  BLOCK: 2,
  GATEWAY: 3,
};

/**
 * Session key recording that a CAS gateway check has already been made, so that
 * a client without a single sign-on session is not bounced to CAS on every
 * request. Delete it to force a fresh gateway check.
 * @type {string}
 */
const GATEWAY_SESSION_FLAG = 'cas_gateway_attempted';

/**
 * Query parameter added to the service URL of a gateway redirect. CAS echoes it
 * back, which lets a gateway check terminate even for a client whose session
 * does not persist between requests (cookies blocked, crawlers).
 *
 * Two consequences are deliberate, because CAS gives no other way to tell a
 * gateway bounce-back apart from an ordinary request:
 *
 * - The marker only covers the return hop, so a client with no usable session
 *   makes one CAS round trip per page view. That is bounded per request rather
 *   than per client, and is the price of not looping forever.
 * - Anyone can put the marker in a link, which suppresses the check for that
 *   one request. Honouring it only when no session exists would reintroduce the
 *   loop, since a session that never persists is indistinguishable from one
 *   that does. The impact is one anonymous render: the pass-through
 *   deliberately records nothing, so the next request checks again.
 *
 * @type {string}
 */
const GATEWAY_QUERY_PARAM = 'cas_gateway';

/**
 * Appends a query parameter to a URL that may already carry a query string.
 */
function appendQueryParam(target, param) {
  return target + (target.indexOf('?') >= 0 ? '&' : '?') + param;
}

/**
 * @typedef {Object} CAS_options
 * @property {string}  cas_url
 * @property {string}  service_url
 * @property {('1.0'|'2.0'|'3.0'|'saml1.1')} [cas_version='3.0']
 * @property {boolean} [renew=false]
 * @property {boolean} [is_dev_mode=false]
 * @property {string}  [dev_mode_user='']
 * @property {Object}  [dev_mode_info={}]
 * @property {string}  [session_name='cas_user']
 * @property {string}  [session_info=false]
 * @property {boolean} [destroy_session=false]
 */

/**
 * @param {CAS_options} options
 * @constructor
 */
function CASAuthentication(options) {
  if (!options || typeof options !== 'object') {
    throw new Error('CAS Authentication was not given a valid configuration object.');
  }
  if (options.cas_url === undefined || options.cas_url === null) {
    throw new Error('CAS Authentication requires a cas_url parameter.');
  }
  if (options.service_url === undefined || options.service_url === null) {
    throw new Error('CAS Authentication requires a service_url parameter.');
  }

  this.cas_version = options.cas_version !== undefined ? options.cas_version : '3.0';

  if (this.cas_version === '1.0') {
    this._validateUri = '/validate';
    this._validate = function (body, callback) {
      const lines = body.split('\n');
      if (lines[0] === 'yes' && lines.length >= 2) {
        return callback(null, lines[1]);
      } if (lines[0] === 'no') {
        return callback(new Error('CAS authentication failed.'));
      }
      return callback(new Error('Response from CAS server was bad.'));
    };
  } else if (this.cas_version === '2.0' || this.cas_version === '3.0') {
    this._validateUri = (this.cas_version === '2.0' ? '/serviceValidate' : '/p3/serviceValidate');
    this._validate = function (body, callback) {
      parseXML(body, {
        trim: true,
        normalize: true,
        explicitArray: false,
        tagNameProcessors: [XMLprocessors.normalize, XMLprocessors.stripPrefix],
      }, (err, result) => {
        if (err) {
          return callback(new Error('Response from CAS server was bad.'));
        }
        try {
          const failure = result.serviceresponse.authenticationfailure;
          if (failure) {
            return callback(new Error(`CAS authentication failed (${failure.$.code}).`));
          }
          const success = result.serviceresponse.authenticationsuccess;
          if (success) {
            return callback(null, success.user, success.attributes);
          }
          return callback(new Error('CAS authentication failed.'));
        } catch (err) {
          console.error(err);
          return callback(new Error('CAS authentication failed.'));
        }
      });
    };
  } else if (this.cas_version === 'saml1.1') {
    this._validateUri = '/samlValidate';
    this._validate = function (body, callback) {
      parseXML(body, {
        trim: true,
        normalize: true,
        explicitArray: false,
        tagNameProcessors: [XMLprocessors.normalize, XMLprocessors.stripPrefix],
      }, (err, result) => {
        if (err) {
          return callback(new Error('Response from CAS server was bad.'));
        }
        try {
          const samlResponse = result.envelope.body.response;
          const success = samlResponse.status.statuscode.$.Value.split(':')[1];
          if (success !== 'Success') {
            return callback(new Error(`CAS authentication failed (${success}).`));
          }
          const attributes = {};
          let attributesArray = samlResponse.assertion.attributestatement.attribute;
          if (!(attributesArray instanceof Array)) {
            attributesArray = [attributesArray];
          }
          attributesArray.forEach((attr) => {
            let thisAttrValue;
            if (attr.attributevalue instanceof Array) {
              thisAttrValue = [];
              attr.attributevalue.forEach((v) => {
                thisAttrValue.push(v._);
              });
            } else {
              thisAttrValue = attr.attributevalue._;
            }
            attributes[attr.$.AttributeName] = thisAttrValue;
          });
          return callback(null, samlResponse.assertion.authenticationstatement.subject.nameidentifier,
            attributes);
        } catch (err) {
          console.error(err);
          return callback(new Error('CAS authentication failed.'));
        }
      });
    };
  } else {
    throw new Error(`The supplied CAS version ("${this.cas_version}") is not supported.`);
  }

  this.cas_url = options.cas_url;
  const parsed_cas_url = url.parse(this.cas_url);
  this.request_client = parsed_cas_url.protocol === 'http:' ? http : https;
  this.cas_host = parsed_cas_url.hostname;
  // Use an explicit port if cas_url carries one, and fall back to the default
  // for the protocol otherwise.
  this.cas_port = parsed_cas_url.port
    ? Number(parsed_cas_url.port)
    : (parsed_cas_url.protocol === 'http:' ? 80 : 443);
  this.cas_path = parsed_cas_url.pathname;

  this.service_url = options.service_url;

  this.renew = options.renew !== undefined ? !!options.renew : false;

  this.is_dev_mode = options.is_dev_mode !== undefined ? !!options.is_dev_mode : false;
  this.dev_mode_user = options.dev_mode_user !== undefined ? options.dev_mode_user : '';
  this.dev_mode_info = options.dev_mode_info !== undefined ? options.dev_mode_info : {};

  this.session_name = options.session_name !== undefined ? options.session_name : 'cas_user';
  this.session_info = ['2.0', '3.0', 'saml1.1'].indexOf(this.cas_version) >= 0 && options.session_info
    !== undefined ? options.session_info : false;
  this.destroy_session = options.destroy_session !== undefined ? !!options.destroy_session : false;

  // Bind the prototype routing methods to this instance of CASAuthentication.
  this.bounce = this.bounce.bind(this);
  this.bounce_redirect = this.bounce_redirect.bind(this);
  this.block = this.block.bind(this);
  this.gateway = this.gateway.bind(this);
  this.logout = this.logout.bind(this);
  this.login = this.login.bind(this);
}

/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce = function (req, res, next) {
  // Handle the request with the bounce authorization type.
  this._handle(req, res, next, AUTH_TYPE.BOUNCE);
};

/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce_redirect = function (req, res, next) {
  // Handle the request with the bounce authorization type.
  this._handle(req, res, next, AUTH_TYPE.BOUNCE_REDIRECT);
};

/**
 * Blocks a request with CAS authentication. If the user's session is not
 * already validated with CAS, they will receive a 401 response.
 */
CASAuthentication.prototype.block = function (req, res, next) {
  // Handle the request with the block authorization type.
  this._handle(req, res, next, AUTH_TYPE.BLOCK);
};

/**
 * Performs a CAS gateway check. If the client already has a single sign-on
 * session they are authenticated transparently; if they do not, the request
 * continues unauthenticated instead of being shown a login form.
 *
 * A client with a working session is checked once - see GATEWAY_SESSION_FLAG
 * and GATEWAY_QUERY_PARAM. A rejected ticket on this path continues
 * unauthenticated rather than returning 401, since the client never asked to
 * log in.
 */
CASAuthentication.prototype.gateway = function (req, res, next) {
  // Handle the request with the gateway authorization type.
  this._handle(req, res, next, AUTH_TYPE.GATEWAY);
};

/**
 * Handle a request with CAS authentication.
 */
CASAuthentication.prototype._handle = function (req, res, next, authType) {
  // If the session has been validated with CAS, no action is required.
  if (req.session[this.session_name]) {
    // If this is a bounce redirect, redirect the authenticated user.
    if (authType === AUTH_TYPE.BOUNCE_REDIRECT) {
      req.session.cas_return_to = req.query.returnTo || url.parse(req.url).path;
      res.redirect(req.session.cas_return_to);
    }
    // Otherwise, allow them through to their request.
    else {
      next();
    }
  }
  // If dev mode is active, set the CAS user to the specified dev user.
  else if (this.is_dev_mode) {
    delete req.session[GATEWAY_SESSION_FLAG];
    req.session.userType = '';
    req.session[this.session_name] = this.dev_mode_user;
    if (this.session_info) {
      req.session[this.session_info] = this.dev_mode_info;
    }
    next();
  }
  // If the authentication type is BLOCK, simply send a 401 response.
  else if (authType === AUTH_TYPE.BLOCK) {
    res.sendStatus(401);
  }
  // If there is a CAS ticket in the query string, validate it with the CAS server.
  else if (req.query && req.query.ticket) {
    this._handleTicket(req, res, next, authType);
  }
  // In gateway mode, make a single silent check for an existing single sign-on
  // session. Arriving here already marked means CAS sent the client back
  // without a ticket, so no such session exists and the request should proceed
  // unauthenticated rather than being bounced to a login form.
  else if (authType === AUTH_TYPE.GATEWAY) {
    if (this._gatewayAlreadyChecked(req)) {
      // Leave the session untouched on the way through: the application may
      // have stored its own state, userType included.
      next();
    } else {
      // renew takes precedence over gateway, which means this redirect asks for
      // a real login rather than a silent check. Recording it as a check done
      // would make the route fall through unauthenticated ever after if the
      // user abandoned the login form, so only record an actual gateway check.
      if (!this.renew) {
        req.session[GATEWAY_SESSION_FLAG] = true;
      }
      req.session.userType = '';
      this._redirectToCas(req, res, true);
    }
  }
  // Otherwise, redirect the user to the CAS login.
  else {
    req.session.userType = '';
    this.login(req, res, next);
  }
};

/**
 * The return path to hand CAS, in the form a browser will send it back in.
 *
 * req.path is already percent-encoded, but Express has decoded
 * req.query.returnTo, so that one has to be re-encoded. Without this the
 * service URL sent to /login would not match the one _serviceForRequest
 * rebuilds on the way back, and CAS would reject the ticket.
 */
CASAuthentication.prototype._returnToFor = function (req) {
  const returnTo = req.query && req.query.returnTo;
  // Only a usable string counts. Express's query parser yields an array for a
  // repeated parameter and an object for a bracketed one, and an empty value has
  // to fall back to the request path rather than redirect the client to nothing.
  if (typeof returnTo === 'string' && returnTo !== '') {
    try {
      return encodeURI(returnTo);
    } catch (err) {
      // encodeURI rejects lone surrogates. Fall back rather than fail the request.
      console.error(err);
    }
  }
  return req.path || '/';
};

/**
 * Reports whether a gateway check has already been made for this client.
 *
 * The session flag is the primary record. The query marker is the fallback for
 * clients whose session does not survive between requests, without which such a
 * client would be redirected to CAS on every request forever.
 */
CASAuthentication.prototype._gatewayAlreadyChecked = function (req) {
  if (req.session && req.session[GATEWAY_SESSION_FLAG]) {
    return true;
  }
  return !!(req.query && req.query[GATEWAY_QUERY_PARAM]);
};

/**
 * Rebuilds the service URL for a request arriving back from CAS.
 *
 * CAS honours a ticket only for the exact service value it was issued for, so
 * this has to reproduce what _redirectToCas sent. CAS appends `ticket` to the
 * service URL it was handed, so removing just that parameter - and preserving
 * the remaining ones byte for byte, rather than re-encoding them - recovers the
 * original value.
 */
CASAuthentication.prototype._serviceForRequest = function (req) {
  const parsed = url.parse(req.url);
  const search = (parsed.search || '').replace(/^\?/, '');
  const kept = search.split('&')
    .filter((pair) => pair !== '' && pair.split('=')[0] !== 'ticket');
  return this.service_url + parsed.pathname + (kept.length ? `?${kept.join('&')}` : '');
};

/**
 * Redirects the client to the CAS login, optionally as a gateway check.
 *
 * @param {boolean} useGateway Request ?gateway=true, so that CAS returns the
 *   client immediately instead of presenting a login form when no single
 *   sign-on session exists.
 */
CASAuthentication.prototype._redirectToCas = function (req, res, useGateway) {
  // Save the return URL in the session. If an explicit return URL is set as a
  // query parameter, use that. Otherwise, just use the URL from the request.
  req.session.cas_return_to = this._returnToFor(req);
  // Set up the query parameters.
  let service = this.service_url + req.session.cas_return_to;
  const query = {};
  // The CAS protocol gives renew precedence when both are supplied, so there is
  // no point sending gateway alongside it.
  if (this.renew) {
    query.renew = this.renew;
  } else if (useGateway) {
    query.gateway = true;
    // Travels back on the service URL, so the check terminates even with no
    // usable session. See _gatewayAlreadyChecked.
    service = appendQueryParam(service, `${GATEWAY_QUERY_PARAM}=1`);
  }
  query.service = service;
  // Redirect to the CAS login.
  res.redirect(this.cas_url + url.format({
    pathname: '/login',
    query,
  }));
};

/**
 * Redirects the client to the CAS login.
 */
CASAuthentication.prototype.login = function (req, res, next) {
  this._redirectToCas(req, res, false);
};

/**
 * Logout the currently logged in CAS user.
 */
CASAuthentication.prototype.logout = function (req, res, next) {
  // Destroy the entire session if the option is set.
  if (this.destroy_session) {
    req.session.destroy((err) => {
      if (err) {
        console.error(err);
      }
    });
  }
  // Otherwise, just destroy the CAS session variables.
  else {
    delete req.session[this.session_name];
    if (this.session_info) {
      delete req.session[this.session_info];
    }
    // Allow a fresh gateway check after logging out. Only needed on this
    // branch: destroying the whole session takes the flag with it, and
    // express-session's destroy() removes req.session outright, so touching it
    // afterwards would throw.
    delete req.session[GATEWAY_SESSION_FLAG];
  }

  // Redirect the client to the CAS logout.
  res.redirect(`${this.cas_url}/logout`);
};

/**
 * Validates a service ticket against the CAS server and reports back the
 * authenticated username and attributes.
 *
 * This is the transport half of ticket handling, deliberately free of any
 * req/res/session coupling so other front ends can reuse it - the Passport
 * strategy in strategy.js wraps exactly this method.
 *
 * @param {Object}   params
 * @param {string}   params.ticket  The service ticket issued by CAS.
 * @param {string}   params.service The service URL the ticket was issued for.
 * @param {string}   [params.host]  Host used to build the SAML 1.1 RequestID.
 * @param {function(Error, string=, Object=)} callback
 */
CASAuthentication.prototype._validateTicket = function (params, callback) {
  const { ticket, service } = params;
  const requestOptions = {
    host: this.cas_host,
    port: this.cas_port,
  };
  let post_data = null;

  // Guard against the response erroring after it has already been parsed,
  // which would otherwise call back twice.
  let settled = false;
  const done = (err, user, attributes) => {
    if (settled) {
      return;
    }
    settled = true;
    callback(err, user, attributes);
  };

  if (['1.0', '2.0', '3.0'].indexOf(this.cas_version) >= 0) {
    requestOptions.method = 'GET';
    requestOptions.path = url.format({
      pathname: this.cas_path + this._validateUri,
      query: {
        service,
        ticket,
      },
    });
  } else if (this.cas_version === 'saml1.1') {
    const now = new Date();
    const request_host = params.host || url.parse(service).hostname || 'localhost';
    post_data = '<?xml version="1.0" encoding="utf-8"?>\n'
      + '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\n'
      + '  <SOAP-ENV:Header/>\n'
      + '  <SOAP-ENV:Body>\n'
      + '    <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1"\n'
      + `      MinorVersion="1" RequestID="_${request_host}.${now.getTime()}"\n`
      + `      IssueInstant="${now.toISOString()}">\n`
      + '      <samlp:AssertionArtifact>\n'
      + `        ${ticket}\n`
      + '      </samlp:AssertionArtifact>\n'
      + '    </samlp:Request>\n'
      + '  </SOAP-ENV:Body>\n'
      + '</SOAP-ENV:Envelope>';

    requestOptions.method = 'POST';
    requestOptions.path = url.format({
      pathname: this.cas_path + this._validateUri,
      query: {
        TARGET: service,
        ticket: '',
      },
    });
    requestOptions.headers = {
      'Content-Type': 'text/xml',
      'Content-Length': Buffer.byteLength(post_data),
    };
  }

  const request = this.request_client.request(requestOptions, (response) => {
    response.setEncoding('utf8');
    let body = '';
    response.on('data', (chunk) => body += chunk);
    response.on('end', () => {
      this._validate(body, (err, user, attributes) => {
        if (err) {
          console.error(err);
        }
        done(err, user, attributes);
      });
    });
    response.on('error', (err) => {
      console.error('Response error from CAS: ', err);
      done(err);
    });
  });

  request.on('error', (err) => {
    console.error('Request error with CAS: ', err);
    done(err);
  });

  if (post_data !== null) {
    request.write(post_data);
  }
  request.end();
};

/**
 * Handles the ticket generated by the CAS login requester and validates it with the CAS login acceptor.
 */
CASAuthentication.prototype._handleTicket = function (req, res, next, authType) {
  this._validateTicket({
    ticket: req.query.ticket,
    service: this._serviceForRequest(req),
    host: req.host,
  }, (err, user, attributes) => {
    if (err) {
      // A gateway check must never block. The client did not ask to log in, so
      // a rejected ticket means carrying on unauthenticated, not a 401.
      if (authType === AUTH_TYPE.GATEWAY) {
        next();
      } else {
        res.sendStatus(401);
      }
      return;
    }
    delete req.session[GATEWAY_SESSION_FLAG];
    req.session[this.session_name] = user;
    if (this.session_info) {
      req.session[this.session_info] = attributes || {};
    }
    res.redirect(req.session.cas_return_to);
  });
};

CASAuthentication.GATEWAY_SESSION_FLAG = GATEWAY_SESSION_FLAG;
CASAuthentication.GATEWAY_QUERY_PARAM = GATEWAY_QUERY_PARAM;

module.exports = CASAuthentication;
