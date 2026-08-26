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
 * Base used to parse a request URL, which arrives as a path rather than an
 * absolute URL. The WHATWG parser requires an absolute URL, so the path is
 * resolved against a host that cannot exist; only the path and query are ever
 * read back off the result.
 * @type {string}
 */
const REQUEST_URL_BASE = 'http://cas-authentication.invalid';

/**
 * Parses a request URL, rejecting anything that escapes the dummy origin.
 *
 * A path is only supposed to address this application. Some values do not:
 * `//host` is protocol-relative, and `/\\host` is the variant browsers
 * normalise to it. Resolved against the base, either produces a URL pointing at
 * another host, which this reports by returning null so the caller can fall
 * back to the site root.
 *
 * The legacy parser this replaced returned `//host` as a *pathname*, which the
 * callers then handed to res.redirect - an off-site redirect from a value the
 * client controls. Reading the origin back is what closes that.
 */
function parseRequestUrl(value) {
  let parsed;
  try {
    parsed = new URL(value, REQUEST_URL_BASE);
  } catch (err) {
    return null;
  }
  return parsed.origin === REQUEST_URL_BASE ? parsed : null;
}

/**
 * Builds a query string the way the legacy url.format did.
 *
 * Deliberately not URLSearchParams: that serialises a space as `+` and
 * percent-encodes `~!*()`, so the `service` value CAS received would no longer
 * be the one the application sent. CAS honours a ticket only for the exact
 * service string it was issued for, which makes this encoding load-bearing
 * rather than cosmetic. encodeURIComponent reproduces the previous bytes.
 */
function formatQuery(params) {
  return Object.keys(params)
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
    .join('&');
}

/**
 * The hostname of an absolute service URL, or null if it will not parse.
 *
 * Only used to label a SAML 1.1 RequestID, so an unparseable value falls back
 * rather than failing the validation.
 */
function serviceHostname(service) {
  try {
    return new URL(service).hostname;
  } catch (err) {
    return null;
  }
}

/**
 * The request URL as the client sent it, including any router mount prefix.
 *
 * Inside a mounted router (`app.use('/portal', router)`) both req.url and
 * req.path are relative to the mount point, so building a service URL from them
 * would hand CAS a path with the prefix missing - and CAS would return the
 * client somewhere that does not exist. req.originalUrl keeps the prefix.
 */
function requestUrl(req) {
  return req.originalUrl || req.url || '/';
}

/**
 * The path portion of the request URL, mount prefix included.
 */
function requestPath(req) {
  const parsed = parseRequestUrl(requestUrl(req));
  if (!parsed) {
    // The client sent a path that resolves to another origin. Falling back to
    // req.path would reintroduce it, since Express derives that from the same
    // string, so this goes to the site root.
    return '/';
  }
  return parsed.pathname || req.path || '/';
}

/**
 * The path and query of the request URL, mount prefix included.
 */
function requestPathWithQuery(req) {
  const parsed = parseRequestUrl(requestUrl(req));
  if (!parsed) {
    return '/';
  }
  return (parsed.pathname || req.path || '/') + parsed.search;
}

/**
 * Whether a client-supplied returnTo is a safe same-origin path.
 *
 * Anything that could carry the client to another origin is rejected: an
 * absolute URL, a protocol-relative `//host` path, the `/\host` variant some
 * browsers normalise to one, and schemes such as `javascript:`. Without this
 * check an attacker can hand a user a link that logs them in through the real
 * CAS server and then lands them on a site of the attacker's choosing, which is
 * a ready-made credential-phishing flow.
 */
function isSafeReturnTo(value) {
  if (typeof value !== 'string' || value === '') {
    return false;
  }
  if (value.charAt(0) !== '/') {
    return false;
  }
  return value.charAt(1) !== '/' && value.charAt(1) !== '\\';
}

/**
 * Appends a query parameter to a URL that may already carry a query string.
 */
function appendQueryParam(target, param) {
  return target + (target.indexOf('?') >= 0 ? '&' : '?') + param;
}

/**
 * Session key this library writes but does not own.
 *
 * userType is not part of the CAS protocol and nothing here ever reads it: the
 * library blanks it on every unauthenticated pass and clears it on logout, and
 * leaves the application to populate it. That is a library reaching into an
 * application's own session state, and it is deprecated - set
 * `manage_user_type: false` to take ownership of the field, which will become
 * the only behaviour in 1.0.
 *
 * The blanking is not pointless, which is why it cannot simply be dropped: the
 * field is what applications tend to authorise on, so a stale value left beside
 * a cleared username invites acting on a privilege that is no longer held. An
 * application that opts out takes on clearing it, or uses destroy_session.
 * @type {string}
 */
const USER_TYPE_SESSION_KEY = 'userType';

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
 * @property {number}  [timeout=10000]
 * @property {boolean} [regenerate_session=true]
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
          this.logger.error('CAS response could not be read: ', err);
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
          this.logger.error('CAS response could not be read: ', err);
          return callback(new Error('CAS authentication failed.'));
        }
      });
    };
  } else {
    throw new Error(`The supplied CAS version ("${this.cas_version}") is not supported.`);
  }

  this.cas_url = options.cas_url;
  let parsed_cas_url;
  try {
    parsed_cas_url = new URL(this.cas_url);
  } catch (err) {
    // The legacy parser accepted anything and left the pieces empty, so a
    // typo surfaced later as a request to an undefined host. Say so here.
    throw new Error(`CAS Authentication was given a cas_url that is not a valid URL ("${this.cas_url}").`);
  }
  this.request_client = parsed_cas_url.protocol === 'http:' ? http : https;
  this.cas_host = parsed_cas_url.hostname;
  // Use an explicit port if cas_url carries one, and fall back to the default
  // for the protocol otherwise. WHATWG parsing reports no port as '', and also
  // drops one that matches the protocol default - which lands on the same
  // number either way.
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

  // Ticket validation is a server-to-server call, so a CAS server that accepts
  // the connection and then never answers would otherwise hold the client's
  // request open forever. 0 disables the timeout.
  const timeout = options.timeout !== undefined ? Number(options.timeout) : 10000;
  if (!Number.isFinite(timeout) || timeout < 0) {
    throw new Error('CAS Authentication requires timeout to be a non-negative number.');
  }
  this.timeout = timeout;

  this.regenerate_session = options.regenerate_session !== undefined
    ? !!options.regenerate_session
    : true;

  // Everything this library reports is a diagnostic, never a thrown error, so
  // without somewhere to send it a failed validation is invisible. console is
  // the default because it always exists; an application with real logging
  // passes its own and gets these lines in the same place as the rest.
  // Deprecated, and default true only so that an existing deployment reading
  // req.session.userType keeps working. See _resetUserType.
  this.manage_user_type = options.manage_user_type !== undefined
    ? !!options.manage_user_type
    : true;

  this.logger = options.logger !== undefined ? options.logger : console;
  if (!this.logger || typeof this.logger.error !== 'function') {
    throw new Error('CAS Authentication requires logger to be an object with an error method.');
  }

  // Bind the prototype routing methods to this instance of CASAuthentication.
  this.validateTicket = this.validateTicket.bind(this);
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
  this._requireSession(req);
  // If the session has been validated with CAS, no action is required.
  if (req.session[this.session_name]) {
    // If this is a bounce redirect, redirect the authenticated user.
    if (authType === AUTH_TYPE.BOUNCE_REDIRECT) {
      // A rejected returnTo falls back to where the client already is. The
      // fallback keeps the query string, unlike the service URL sent to CAS,
      // because this redirect stays inside the application.
      const returnTo = req.query && req.query.returnTo;
      req.session.cas_return_to = isSafeReturnTo(returnTo)
        ? returnTo
        : requestPathWithQuery(req);
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
    this._resetUserType(req);
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
      this._resetUserType(req);
      this._redirectToCas(req, res, true);
    }
  }
  // Otherwise, redirect the user to the CAS login.
  else {
    this._resetUserType(req);
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
  // Only a safe same-origin path counts. That rules out an off-site redirect,
  // and also the array Express yields for a repeated parameter, the object it
  // yields for a bracketed one, and an empty value that would otherwise redirect
  // the client to nothing.
  if (isSafeReturnTo(returnTo)) {
    try {
      return encodeURI(returnTo);
    } catch (err) {
      // encodeURI rejects lone surrogates. Fall back rather than fail the request.
      this.logger.error('returnTo could not be encoded, falling back to the request path: ', err);
    }
  }
  return requestPath(req);
};

/**
 * Asserts that a session middleware is in place.
 *
 * Every entry point reads or writes the session, so this says so plainly rather
 * than failing later with a TypeError about a property of undefined. Forgetting
 * the session middleware is the most common way to misconfigure this library.
 */
CASAuthentication.prototype._resetUserType = function (req) {
  if (this.manage_user_type) {
    req.session[USER_TYPE_SESSION_KEY] = '';
  }
};

CASAuthentication.prototype._requireSession = function (req) {
  if (!req.session) {
    throw new Error('CAS Authentication requires session support. Add express-session '
      + '(or another middleware that populates req.session) before this middleware.');
  }
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
  const parsed = parseRequestUrl(requestUrl(req));
  if (!parsed) {
    return this.service_url + requestPath(req);
  }
  const search = parsed.search.replace(/^\?/, '');
  const kept = search.split('&')
    .filter((pair) => pair !== '' && pair.split('=')[0] !== 'ticket');
  return this.service_url + (parsed.pathname || requestPath(req))
    + (kept.length ? `?${kept.join('&')}` : '');
};

/**
 * Redirects the client to the CAS login, optionally as a gateway check.
 *
 * @param {boolean} useGateway Request ?gateway=true, so that CAS returns the
 *   client immediately instead of presenting a login form when no single
 *   sign-on session exists.
 */
CASAuthentication.prototype._redirectToCas = function (req, res, useGateway) {
  this._requireSession(req);
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
  res.redirect(`${this.cas_url}/login?${formatQuery(query)}`);
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
  this._requireSession(req);
  // Destroy the entire session if the option is set.
  if (this.destroy_session) {
    req.session.destroy((err) => {
      if (err) {
        this.logger.error('Session store failed to destroy the session on logout: ', err);
      }
    });
  }
  // Otherwise, just destroy the CAS session variables.
  else {
    delete req.session[this.session_name];
    if (this.session_info) {
      delete req.session[this.session_info];
    }
    // Clear everything else this library writes. Only needed on this branch -
    // destroying the whole session takes all of it along, and express-session's
    // destroy() removes req.session outright, so touching it afterwards would
    // throw.
    delete req.session[GATEWAY_SESSION_FLAG];
    delete req.session.cas_return_to;
    // userType is authorisation-relevant: leaving the previous user's value
    // behind while their username is gone lets an application that reads it
    // alone act on a stale privilege. An application that has opted out of
    // userType clears it itself, or sets destroy_session.
    if (this.manage_user_type) {
      delete req.session[USER_TYPE_SESSION_KEY];
    }
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
 * Called with a callback it reports through that. Called without one it
 * returns a promise, which is the form to prefer in new code - see
 * validateTicket below.
 *
 * @param {Object}   params
 * @param {string}   params.ticket  The service ticket issued by CAS.
 * @param {string}   params.service The service URL the ticket was issued for.
 * @param {string}   [params.host]  Host used to build the SAML 1.1 RequestID.
 * @param {function(Error, string=, Object=)} [callback]
 * @returns {Promise<{user: string, attributes: Object}>|undefined}
 */
CASAuthentication.prototype._validateTicket = function (params, callback) {
  if (callback === undefined) {
    return this.validateTicket(params);
  }
  if (typeof callback !== 'function') {
    // Otherwise this surfaces as a TypeError from inside the response handler,
    // long after the call that caused it.
    throw new Error('CAS Authentication was given a _validateTicket callback that is not a function.');
  }
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
    requestOptions.path = `${this.cas_path + this._validateUri}?${formatQuery({ service, ticket })}`;
  } else if (this.cas_version === 'saml1.1') {
    const now = new Date();
    const request_host = params.host || serviceHostname(service) || 'localhost';
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
    requestOptions.path = `${this.cas_path + this._validateUri}?${formatQuery({ TARGET: service, ticket: '' })}`;
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
          this.logger.error('CAS rejected the ticket: ', err);
          done(err);
          return;
        }
        // CAS reported success without a usable username. Storing an empty
        // string would leave the client looking unauthenticated on every later
        // request, which loops between the application and CAS indefinitely.
        if (user === undefined || user === null || String(user).trim() === '') {
          const blank = new Error('CAS authentication succeeded without a username.');
          this.logger.error(blank);
          done(blank);
          return;
        }
        done(null, user, attributes);
      });
    });
    response.on('error', (err) => {
      this.logger.error('Response error from CAS: ', err);
      done(err);
    });
  });

  request.on('error', (err) => {
    this.logger.error('Request error with CAS: ', err);
    done(err);
  });

  if (this.timeout > 0) {
    // setTimeout only reports socket inactivity; destroying the request is what
    // turns that into an error the caller sees.
    request.setTimeout(this.timeout, () => {
      request.destroy(new Error(`CAS request timed out after ${this.timeout}ms.`));
    });
  }

  if (post_data !== null) {
    request.write(post_data);
  }
  request.end();
  return undefined;
};

/**
 * Validates a service ticket against the CAS server and resolves with the
 * authenticated identity.
 *
 * The promise-returning form of _validateTicket, and the one to prefer: it is
 * the whole public surface of ticket validation without a request, a session or
 * a callback, which is what an alternative front end needs. Rejects with the
 * validation error rather than resolving with a falsy user, so a failure cannot
 * be missed by forgetting to check.
 *
 * @param {Object} params As _validateTicket.
 * @returns {Promise<{user: string, attributes: Object}>}
 */
CASAuthentication.prototype.validateTicket = function (params) {
  return new Promise((resolve, reject) => {
    this._validateTicket(params, (err, user, attributes) => {
      if (err) {
        reject(err);
        return;
      }
      // Normalised to {} so a caller can read an attribute without guarding
      // first; CAS 1.0 never supplies attributes at all.
      resolve({ user, attributes: attributes || {} });
    });
  });
};

/**
 * Stores a validated CAS identity on the session, giving the client a fresh
 * session id first.
 *
 * Regenerating defeats session fixation: without it, an attacker who can plant a
 * session cookie on a victim before they log in still holds a valid handle on
 * the authenticated session afterwards. express-session's regenerate() starts
 * from an empty session, so application data is copied across - only the id
 * changes.
 *
 * Falls back to storing in place when regeneration is switched off or the
 * session middleware does not offer it.
 */
CASAuthentication.prototype._establishSession = function (req, user, attributes, callback) {
  const store = () => {
    delete req.session[GATEWAY_SESSION_FLAG];
    req.session[this.session_name] = user;
    if (this.session_info) {
      req.session[this.session_info] = attributes || {};
    }
    callback();
  };

  if (!this.regenerate_session || !req.session || typeof req.session.regenerate !== 'function') {
    store();
    return;
  }

  const preserved = {};
  Object.keys(req.session).forEach((key) => {
    // The new session brings its own cookie; everything else is the
    // application's and should survive.
    if (key !== 'cookie') {
      preserved[key] = req.session[key];
    }
  });

  req.session.regenerate((err) => {
    if (err) {
      // The store failed to drop the old record. express-session has still
      // handed us a fresh session, so carry on rather than failing the login.
      this.logger.error('Session store failed to regenerate the session on login: ', err);
    }
    Object.assign(req.session, preserved);
    store();
  });
};

/**
 * Handles the ticket generated by the CAS login requester and validates it with the CAS login acceptor.
 */
CASAuthentication.prototype._handleTicket = function (req, res, next, authType) {
  this._validateTicket({
    ticket: req.query.ticket,
    service: this._serviceForRequest(req),
    host: req.hostname || req.host,
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
    this._establishSession(req, user, attributes, () => {
      // cas_return_to is missing if the session did not survive the round trip,
      // or if the client arrived at a ticket URL directly. Redirecting to the
      // current path still lands them in the right place, minus the spent ticket.
      res.redirect(req.session.cas_return_to || requestPath(req));
    });
  });
};

CASAuthentication.prototype._requestPath = function (req) {
  return requestPath(req);
};

// Shared with the Passport strategy, which builds the same login URL.
CASAuthentication.formatQuery = formatQuery;
CASAuthentication.USER_TYPE_SESSION_KEY = USER_TYPE_SESSION_KEY;
CASAuthentication.GATEWAY_SESSION_FLAG = GATEWAY_SESSION_FLAG;
CASAuthentication.GATEWAY_QUERY_PARAM = GATEWAY_QUERY_PARAM;

module.exports = CASAuthentication;
