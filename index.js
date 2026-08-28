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
 *
 * Reading the origin is necessary and not sufficient. `//host` does resolve to
 * another origin and is caught by that check; `/..//host` does not, because the
 * dot segment resolves away and leaves this origin with a *pathname* of
 * `//host`, which is protocol-relative again once res.redirect writes it into a
 * Location header.
 */
function parseRequestUrl(value) {
  let parsed;
  try {
    parsed = new URL(value, REQUEST_URL_BASE);
  } catch (err) {
    return null;
  }
  if (parsed.origin !== REQUEST_URL_BASE) {
    return null;
  }
  // `/..//host`, `/%2e%2e//host` and `/a/../../..//host` all normalise to this,
  // as does `/../\host`, which produces the shape isSafeReturnTo rejects on sight.
  if (parsed.pathname.charAt(1) === '/' || parsed.pathname.charAt(1) === '\\') {
    return null;
  }
  return parsed;
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
 * The text of a SAML 1.1 <AttributeValue>.
 *
 * xml2js puts the text on `_` when the element carries an attribute (real CAS
 * servers send `xsi:type`) and gives a plain string when it does not, so reading
 * `._` unconditionally discarded a value the CAS server had released.
 */
function samlAttributeValue(value) {
  if (value === null || value === undefined) {
    return undefined;
  }
  return typeof value === 'object' ? value._ : value;
}

/**
 * The username out of a parsed CAS response, or null if there is none.
 *
 * xml2js represents an element carrying an attribute as an object with the text
 * on `_`, so `<cas:user format="upn">` yielded an object where both .d.ts files
 * promise a string, and `[object Object]` became the session username.
 */
function casUsername(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value !== null && typeof value === 'object' && typeof value._ === 'string') {
    return value._;
  }
  return null;
}

/**
 * Escapes text interpolated into the SAML 1.1 SOAP request.
 *
 * The ticket arrives from the client and the host from a request header, and
 * written raw either one could close its element and add markup of its own to
 * the document handed to the CAS server.
 */
function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * The error for a CAS response that could not be read at all, tagged so the
 * caller can tell it apart from CAS actually rejecting the ticket.
 *
 * Both used to be logged as "CAS rejected the ticket", so a CAS server that was
 * down or answering with a proxy error page read in the log exactly like a user
 * presenting a bad ticket.
 */
function badResponse() {
  const err = new Error('Response from CAS server was bad.');
  err.casResponseUnreadable = true;
  return err;
}

/**
 * A path with any fragment removed.
 *
 * A fragment means nothing to CAS: sent on the service URL, it comes back with
 * `?ticket=` inside the fragment, where the application cannot read it. The
 * fragment is kept for the final redirect and dropped from the service URL.
 */
function stripFragment(value) {
  const hash = value.indexOf('#');
  return hash < 0 ? value : value.slice(0, hash);
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
 * @property {(string|false)} [session_info=false]
 * @property {boolean} [destroy_session=false]
 * @property {number}  [timeout=10000]
 * @property {number}  [max_response_bytes=1048576]
 * @property {boolean} [regenerate_session=true]
 * @property {Object}  [logger=console]
 * @property {boolean} [manage_user_type=true]
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
      return callback(badResponse());
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
          return callback(badResponse());
        }
        let failure = null;
        let user;
        let attributes;
        try {
          const reported = result.serviceresponse.authenticationfailure;
          if (reported) {
            failure = new Error(`CAS authentication failed (${reported.$.code}).`);
          } else {
            const success = result.serviceresponse.authenticationsuccess;
            if (success) {
              ({ user, attributes } = success);
            } else {
              failure = new Error('CAS authentication failed.');
            }
          }
        } catch (readErr) {
          this.logger.error('CAS response could not be read: ', readErr);
          failure = new Error('CAS authentication failed.');
        }
        // Outside the try deliberately. Everything downstream of this callback
        // belongs to the application (the session store, res.redirect, a Passport
        // verify callback), and inside the try an exception from any of them was
        // caught here, reported as an unreadable CAS response, and dropped by the
        // settled guard, leaving the request with no response at all.
        return callback(failure, user, attributes);
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
          return callback(badResponse());
        }
        let failure = null;
        let user;
        let attributes;
        try {
          const samlResponse = result.envelope.body.response;
          const success = samlResponse.status.statuscode.$.Value.split(':')[1];
          if (success !== 'Success') {
            failure = new Error(`CAS authentication failed (${success}).`);
          } else {
            attributes = {};
            // A server releasing no attributes omits the AttributeStatement,
            // and an attribute may carry no value; reaching through either threw,
            // and the catch below turned that into a failed login. The 2.0/3.0
            // parser has always tolerated the equivalent.
            const statement = samlResponse.assertion.attributestatement;
            let attributesArray = statement ? statement.attribute : [];
            if (attributesArray === undefined || attributesArray === null) {
              attributesArray = [];
            }
            if (!(attributesArray instanceof Array)) {
              attributesArray = [attributesArray];
            }
            attributesArray.forEach((attr) => {
              if (!attr || !attr.$ || attr.$.AttributeName === undefined) {
                return;
              }
              const value = attr.attributevalue;
              attributes[attr.$.AttributeName] = value instanceof Array
                ? value.map(samlAttributeValue)
                : samlAttributeValue(value);
            });
            user = samlResponse.assertion.authenticationstatement.subject.nameidentifier;
          }
        } catch (readErr) {
          this.logger.error('CAS response could not be read: ', readErr);
          failure = new Error('CAS authentication failed.');
        }
        // Outside the try for the same reason as the 2.0/3.0 parser above.
        return callback(failure, user, attributes);
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
  // Anything that is not http: was treated as https:, so `htps://cas.example.edu`
  // validated tickets over TLS while sending the browser to a login URL it cannot
  // navigate to; `javascript:...` parses with no hostname at all.
  if (parsed_cas_url.protocol !== 'http:' && parsed_cas_url.protocol !== 'https:') {
    throw new Error('CAS Authentication requires cas_url to be an http or https URL, got '
      + `"${this.cas_url}".`);
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
  // A cas_url of `https://host/` leaves a pathname of `/`, which concatenated
  // with the validate URI gives `//p3/serviceValidate`; some deployments 404 on it.
  this.cas_path = parsed_cas_url.pathname === '/' ? '' : parsed_cas_url.pathname.replace(/\/$/, '');

  // service_url was the one required option nothing checked, though every
  // redirect and every service value concatenates a path onto it; a trailing
  // slash produced `https://app.example.com//dashboard`.
  let parsed_service_url;
  try {
    parsed_service_url = new URL(options.service_url);
  } catch (err) {
    throw new Error('CAS Authentication was given a service_url that is not a valid URL '
      + `("${options.service_url}").`);
  }
  if (parsed_service_url.protocol !== 'http:' && parsed_service_url.protocol !== 'https:') {
    throw new Error('CAS Authentication requires service_url to be an http or https URL, got '
      + `"${options.service_url}".`);
  }
  this.service_url = String(options.service_url).replace(/\/+$/, '');

  this.renew = options.renew !== undefined ? !!options.renew : false;

  this.is_dev_mode = options.is_dev_mode !== undefined ? !!options.is_dev_mode : false;
  this.dev_mode_user = options.dev_mode_user !== undefined ? options.dev_mode_user : '';
  this.dev_mode_info = options.dev_mode_info !== undefined ? options.dev_mode_info : {};

  // Dev mode authenticates every request as dev_mode_user without contacting CAS,
  // so it must never reach production quietly. It did: nothing reached any
  // channel, and `is_dev_mode: 'false'` (the shape an environment variable
  // arrives in) is a non-empty string, so it switched dev mode on.
  if (this.is_dev_mode) {
    if (typeof this.dev_mode_user !== 'string' || this.dev_mode_user === '') {
      // The library refuses this value from a real CAS server: a blank username
      // is authenticated as far as the middleware is concerned and anonymous to
      // every `if (req.session.cas_user)` in the application.
      throw new Error('CAS Authentication requires a non-empty dev_mode_user when '
        + 'is_dev_mode is set, since a blank username authenticates as nobody.');
    }
    this.logger_warning_dev_mode = `CAS Authentication is in DEV MODE: every request is `
      + `authenticated as "${this.dev_mode_user}" and ${options.cas_url} is never contacted.`;
  }

  this.session_name = options.session_name !== undefined ? options.session_name : 'cas_user';
  this.session_info = ['2.0', '3.0', 'saml1.1'].indexOf(this.cas_version) >= 0 && options.session_info
    !== undefined ? options.session_info : false;
  this.destroy_session = options.destroy_session !== undefined ? !!options.destroy_session : false;

  // Ticket validation is a server-to-server call, so a CAS server that accepts
  // the connection and then never answers would otherwise hold the client's
  // request open forever. 0 disables the timeout.
  // Only a number, or a string that is one. `Number()` alone turned null, false
  // and [] into 0, the value that means "wait for ever", so the malformed values
  // that got through were exactly the ones that disabled the timeout.
  if (options.timeout !== undefined
    && typeof options.timeout !== 'number' && typeof options.timeout !== 'string') {
    throw new Error('CAS Authentication requires timeout to be a non-negative number.');
  }
  const timeout = options.timeout !== undefined ? Number(options.timeout) : 10000;
  if (!Number.isFinite(timeout) || timeout < 0) {
    throw new Error('CAS Authentication requires timeout to be a non-negative number.');
  }
  this.timeout = timeout;

  // The CAS response is buffered before it is parsed, so it needs a ceiling. The
  // default is generous next to a SAML assertion with a large attribute release
  // (tens of kilobytes); 0 disables it.
  if (options.max_response_bytes !== undefined
    && (typeof options.max_response_bytes !== 'number'
      || !Number.isFinite(options.max_response_bytes)
      || options.max_response_bytes < 0)) {
    throw new Error('CAS Authentication requires max_response_bytes to be a non-negative number.');
  }
  this.max_response_bytes = options.max_response_bytes !== undefined
    ? options.max_response_bytes
    : 1048576;

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

  // Said once, at construction, on the one channel a logger is required to have.
  if (this.logger_warning_dev_mode) {
    this.logger.error(this.logger_warning_dev_mode);
    delete this.logger_warning_dev_mode;
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
      const here = requestPathWithQuery(req);
      const target = isSafeReturnTo(returnTo) ? returnTo : here;
      // Except that "where the client already is" is this route: the redirect
      // returns the client here in the same state, to be redirected again.
      // bounce_redirect exists to send a client somewhere else, so an absent or
      // rejected returnTo has no destination and the site root is what is left.
      if (target !== here) {
        req.session.cas_return_to = target;
        res.redirect(target);
      } else if (requestUrl(req) === '/') {
        // Nowhere left to send them, so the request is handed to the
        // application instead. The test is on the URL the client sent, not on
        // `here`: a path rejected as off-origin also collapses to `/`.
        next();
      } else {
        req.session.cas_return_to = '/';
        res.redirect('/');
      }
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
      // CAS has returned this client without a ticket, so they hold no single
      // sign-on session, and they are standing on the bare service URL rather
      // than the page they asked for: a visitor to `/browse?q=cats` was left on
      // `/browse` by a check that is supposed to be invisible. The session
      // remembers where they were going.
      const destination = req.session && req.session.cas_return_to;
      if (req.query && req.query[GATEWAY_QUERY_PARAM]
        && destination && destination !== this._returnPathForRequest(req)) {
        delete req.session.cas_return_to;
        res.redirect(destination);
        return;
      }
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
  // Otherwise, redirect the user to the CAS login. Straight to _redirectToCas
  // rather than through login(), which routes back through here and would recurse.
  else {
    this._resetUserType(req);
    this._redirectToCas(req, res, false);
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
CASAuthentication.prototype._returnToFor = function (req, keepQuery) {
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
  // With no returnTo the request itself is the destination, and the client's own
  // query string is part of it; the service URL drops it. See _redirectToCas.
  return keepQuery ? this._returnPathForRequest(req) : requestPath(req);
};

/**
 * Blanks the deprecated userType key, if this library is still managing it.
 * See USER_TYPE_SESSION_KEY.
 */
CASAuthentication.prototype._resetUserType = function (req) {
  if (this.manage_user_type) {
    req.session[USER_TYPE_SESSION_KEY] = '';
  }
};

/**
 * Asserts that a session middleware is in place.
 *
 * Every entry point reads or writes the session, so this says so plainly rather
 * than failing later with a TypeError about a property of undefined. Forgetting
 * the session middleware is the most common way to misconfigure this library.
 */
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
  return this.service_url + this._returnPathForRequest(req);
};

/**
 * The current request as a path to send a client back to: everything the client
 * asked for, minus the spent ticket.
 *
 * The ticket is the only parameter dropped, and the rest are preserved byte for
 * byte rather than re-encoded, because this doubles as the service value CAS has
 * to match exactly.
 *
 * It is also the destination once a ticket has been validated, and dropping the
 * query there cost gateway mode the `cas_gateway=1` marker that ends the check:
 * a client whose session does not persist was sent to CAS on every request, and
 * every visitor to a gateway route lost their own parameters with it.
 */
CASAuthentication.prototype._returnPathForRequest = function (req) {
  const parsed = parseRequestUrl(requestUrl(req));
  if (!parsed) {
    return requestPath(req);
  }
  const search = parsed.search.replace(/^\?/, '');
  const kept = search.split('&')
    .filter((pair) => pair !== '' && pair.split('=')[0] !== 'ticket');
  return (parsed.pathname || requestPath(req))
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
  req.session.cas_return_to = this._returnToFor(req, true);
  // The service URL is deliberately not that value: it carries no query string
  // of the application's own (page parameters are never handed to CAS, nor
  // written to its access logs) and no fragment, which would come back with
  // `?ticket=` buried inside it. The session carries the full destination.
  let service = this.service_url + stripFragment(this._returnToFor(req, false));
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
 * A login endpoint: sends the client to CAS, and completes the round trip when
 * CAS sends them back.
 *
 * Mounted as a route (`app.get('/login', cas.login)`), which makes the route its
 * own service URL, so CAS returns the client to it carrying a ticket.
 * Redirecting unconditionally to CAS, as this used to, never validated that
 * ticket: the client went straight back to CAS, which issued another one, and
 * every hop cost a service ticket. It now handles all three states, as _handle
 * already does for bounce_redirect.
 */
CASAuthentication.prototype.login = function (req, res, next) {
  this._handle(req, res, next, AUTH_TYPE.BOUNCE_REDIRECT);
};

/**
 * Logout the currently logged in CAS user.
 */
CASAuthentication.prototype.logout = function (req, res, next) {
  this._requireSession(req);
  const casLogout = `${this.cas_url}/logout`;
  // Destroy the entire session if the option is set.
  if (this.destroy_session) {
    if (typeof req.session.destroy !== 'function') {
      // regenerate is probed before use in _establishSession; destroy was not,
      // so a session middleware without one answered logout with a TypeError 500
      // and left the user logged in. Fall back to the other branch's behaviour.
      this.logger.error('destroy_session is set but the session has no destroy method; '
        + 'clearing the CAS session keys instead.');
      this._clearSessionKeys(req);
      res.redirect(casLogout);
      return;
    }
    // The redirect used to be sent without waiting, so a store that failed to
    // delete the record still told the client the logout had worked.
    req.session.destroy((err) => {
      if (err) {
        this.logger.error('Session store failed to destroy the session on logout: ', err);
        if (next) {
          next(err);
          return;
        }
      }
      res.redirect(casLogout);
    });
    return;
  }
  // Otherwise, just destroy the CAS session variables.
  this._clearSessionKeys(req);

  // Persist the cleared session before the client is sent anywhere, so a store
  // that cannot write says so rather than leaving a record that still names them.
  if (typeof req.session.save === 'function') {
    req.session.save((err) => {
      if (err) {
        this.logger.error('Session store failed to save the session on logout: ', err);
        if (next) {
          next(err);
          return;
        }
      }
      res.redirect(casLogout);
    });
    return;
  }

  // Redirect the client to the CAS logout.
  res.redirect(casLogout);
};

/**
 * Removes everything this library writes to the session, leaving the
 * application's own keys alone. The counterpart to destroy_session.
 */
CASAuthentication.prototype._clearSessionKeys = function (req) {
  // Passport keeps the logged-in user under its own session key, so a client who
  // signed in through the bundled strategy was shown the CAS logout page while
  // req.user carried on as before. req.logout exists only when Passport is
  // installed, and 0.6 requires the callback that 0.5 ignores.
  if (typeof req.logout === 'function') {
    try {
      req.logout(() => {});
    } catch (err) {
      this.logger.error('Passport failed to clear its session on logout: ', err);
    }
  }
  delete req.session[this.session_name];
  if (this.session_info) {
    delete req.session[this.session_info];
  }
  // Destroying the whole session takes all of this along instead, and
  // express-session's destroy() removes req.session outright, so this is only
  // ever reached on the branch where the session survives.
  delete req.session[GATEWAY_SESSION_FLAG];
  delete req.session.cas_return_to;
  // userType is authorisation-relevant: leaving the previous user's value
  // behind while their username is gone lets an application that reads it
  // alone act on a stale privilege. An application that has opted out of
  // userType clears it itself, or sets destroy_session.
  if (this.manage_user_type) {
    delete req.session[USER_TYPE_SESSION_KEY];
  }
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
      // Escaped: the ticket comes from the client's query string and the host
      // from a request header.
      + `      MinorVersion="1" RequestID="_${escapeXml(request_host)}.${now.getTime()}"\n`
      + `      IssueInstant="${now.toISOString()}">\n`
      + '      <samlp:AssertionArtifact>\n'
      + `        ${escapeXml(ticket)}\n`
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
    let oversized = false;
    response.on('data', (chunk) => {
      if (oversized) {
        return;
      }
      body += chunk;
      // A CAS response is a few kilobytes. Without a cap, a server answering with
      // an endless body is buffered into this process until memory runs out.
      if (this.max_response_bytes > 0 && Buffer.byteLength(body) > this.max_response_bytes) {
        oversized = true;
        request.destroy(new Error(
          `CAS response exceeded max_response_bytes (${this.max_response_bytes}).`,
        ));
      }
    });
    response.on('end', () => {
      if (oversized) {
        return;
      }
      // A CAS server that is down or behind a proxy answers with an error status
      // and an HTML body, which parses as "authentication failed" and was logged
      // as CAS rejecting the ticket. The status says which it was.
      if (response.statusCode < 200 || response.statusCode >= 300) {
        const status = new Error(
          `CAS server answered ticket validation with HTTP ${response.statusCode}.`,
        );
        this.logger.error(status);
        done(status);
        return;
      }
      this._validate(body, (err, user, attributes) => {
        if (err) {
          this.logger.error(err.casResponseUnreadable
            ? 'CAS response could not be read: '
            : 'CAS rejected the ticket: ', err);
          done(err);
          return;
        }
        // CAS reported success without a usable username. Storing an empty
        // string would leave the client looking unauthenticated on every later
        // request, which loops between the application and CAS indefinitely; a
        // non-string is just as unusable. See casUsername.
        const name = casUsername(user);
        if (name === null || name.trim() === '') {
          const blank = new Error('CAS authentication succeeded without a username.');
          this.logger.error(blank);
          done(blank);
          return;
        }
        done(null, name, attributes);
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
    // A deadline for the whole call, not the socket-inactivity timer this used to
    // be: request.setTimeout() only fires when nothing arrives for the interval,
    // so a CAS server sending one byte at a time reset it indefinitely and the
    // budget an application set never fired. Destroying the request is what turns
    // the deadline into an error the caller sees.
    const deadline = setTimeout(() => {
      request.destroy(new Error(`CAS request timed out after ${this.timeout}ms.`));
    }, this.timeout);
    // Never hold the event loop open on the library's account.
    if (typeof deadline.unref === 'function') {
      deadline.unref();
    }
    const clear = () => clearTimeout(deadline);
    request.on('close', clear);
    request.on('error', clear);
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
    // The session can be gone by the time a CAS round trip returns, destroyed by
    // another request on the same session; writing to it then threw from inside
    // an HTTP response handler, where there is no request left to fail.
    if (!req.session) {
      callback(new Error('The session was destroyed while the CAS ticket was being validated.'));
      return;
    }
    delete req.session[GATEWAY_SESSION_FLAG];
    req.session[this.session_name] = user;
    if (this.session_info) {
      req.session[this.session_info] = attributes || {};
    }
    // Write the authenticated session before the client is redirected. Otherwise
    // the redirect races the store (express-session saves when the response
    // ends), so a rejected write reached the browser as a login loop with
    // nothing on the logger to say why.
    if (typeof req.session.save === 'function') {
      req.session.save((err) => {
        if (err) {
          this.logger.error('Session store failed to save the session on login: ', err);
          callback(err);
          return;
        }
        callback();
      });
      return;
    }
    callback();
  };

  if (!this.regenerate_session || !req.session || typeof req.session.regenerate !== 'function') {
    // Session fixation is why regenerate_session defaults to true, so falling
    // back to storing in place is a real reduction in protection; it happened
    // silently, so an application that had asked for the defence could not tell.
    if (this.regenerate_session && req.session && typeof req.session.regenerate !== 'function') {
      this.logger.error('The session middleware in use has no regenerate() method, so the '
        + 'session id cannot be rotated on login and this application is open to session '
        + 'fixation. Use express-session, or set regenerate_session: false to silence this.');
    }
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
    this._establishSession(req, user, attributes, (sessionErr) => {
      if (sessionErr) {
        // However the validation went, the client is not logged in, so this goes
        // to Express rather than into a redirect loop that cannot terminate.
        next(sessionErr);
        return;
      }
      // cas_return_to is missing if the session did not survive the round trip,
      // or if the client arrived at a ticket URL directly. The request itself
      // lands them in the right place, minus the spent ticket; keeping the rest
      // of the query is what lets a session-less gateway check terminate.
      const destination = (req.session && req.session.cas_return_to)
        || this._returnPathForRequest(req);
      try {
        res.redirect(destination);
      } catch (redirectErr) {
        // A res.redirect that throws used to be caught by the response parser
        // and dropped, hanging the request.
        next(redirectErr);
      }
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
