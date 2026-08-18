'use strict';

const url = require('url');
const CASAuthentication = require('./index.js');

/**
 * A Passport strategy for CAS.
 *
 * This is a thin wrapper: ticket validation, protocol selection and XML parsing
 * are all delegated to CASAuthentication#_validateTicket, so the strategy
 * inherits support for CAS 1.0, 2.0, 3.0 and SAML 1.1 without duplicating any
 * of it.
 *
 * No dependency on `passport` is required. Passport supplies success(), fail(),
 * redirect(), pass() and error() on the strategy instance at authenticate time.
 *
 * @typedef {Object} CAS_profile
 * @property {string} provider   Always "cas".
 * @property {string} id         The CAS username.
 * @property {string} user       The CAS username.
 * @property {Object} attributes Attributes released by CAS, {} if none.
 *
 * @param {Object}   options              CASAuthentication options, or {cas: instance}.
 * @param {Object}   [options.cas]        An existing CASAuthentication instance to reuse.
 * @param {string}   [options.name='cas'] The name Passport registers the strategy under.
 * @param {boolean}  [options.passReqToCallback=false] Pass req as the verify callback's first argument.
 * @param {function} [verify]             verify(profile, done), or verify(req, profile, done).
 * @constructor
 */
function Strategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!options || typeof options !== 'object') {
    throw new Error('CAS Strategy was not given a valid configuration object.');
  }
  if (verify !== undefined && typeof verify !== 'function') {
    throw new Error('CAS Strategy verify callback must be a function.');
  }

  this.name = options.name || 'cas';
  this.cas = options.cas instanceof CASAuthentication
    ? options.cas
    : new CASAuthentication(options);
  this._verify = verify;
  this._passReqToCallback = !!options.passReqToCallback;
}

/**
 * The service URL to hand CAS when redirecting a client to log in.
 *
 * The request path only: the page's own query string is deliberately left out,
 * matching what the core middleware sends, so page parameters are not handed to
 * the CAS server or written to its access logs. Nothing is lost on the way
 * back, because CAS returns only the service value it was given - which is what
 * makes _serviceUrl below reproduce this exactly.
 */
Strategy.prototype._serviceForRedirect = function (req) {
  return this.cas.service_url + (req.path || url.parse(req.url).pathname || '/');
};

/**
 * The service URL to send when validating a ticket: whatever CAS returned the
 * client to, minus the ticket. Reconstructed from the request rather than
 * remembered in the session, so concurrent tabs cannot cross-contaminate.
 */
Strategy.prototype._serviceUrl = function (req) {
  return this.cas._serviceForRequest(req);
};

/**
 * Builds the CAS login URL to bounce an unauthenticated client to.
 */
Strategy.prototype._loginUrl = function (service, useGateway) {
  const query = { service };
  // renew takes precedence over gateway in the CAS protocol.
  if (this.cas.renew) {
    query.renew = this.cas.renew;
  } else if (useGateway) {
    query.gateway = true;
    // Echoed back by CAS, so the check terminates even without a session.
    query.service = `${service}${service.indexOf('?') >= 0 ? '&' : '?'}`
      + `${CASAuthentication.GATEWAY_QUERY_PARAM}=1`;
  }
  return this.cas.cas_url + url.format({ pathname: '/login', query });
};

/**
 * Authenticate a request.
 *
 * @param {Object}  req
 * @param {Object}  [options]
 * @param {boolean} [options.gateway] Make a silent gateway check rather than
 *   redirecting to a login form. Requires a session, and results in pass()
 *   when the client turns out to have no single sign-on session.
 */
Strategy.prototype.authenticate = function (req, options) {
  const opts = options || {};
  const ticket = req.query && req.query.ticket;

  if (!ticket) {
    const service = this._serviceForRedirect(req);
    if (!opts.gateway) {
      this.redirect(this._loginUrl(service, false));
      return;
    }
    if (this.cas._gatewayAlreadyChecked(req)) {
      // CAS returned the client without a ticket: no single sign-on session.
      this.pass();
      return;
    }
    // Recorded in the session when there is one, and on the service URL either
    // way, so the check cannot loop.
    if (req.session) {
      req.session[CASAuthentication.GATEWAY_SESSION_FLAG] = true;
    }
    this.redirect(this._loginUrl(service, true));
    return;
  }

  this.cas._validateTicket({
    ticket, service: this._serviceUrl(req), host: req.host,
  }, (err, user, attributes) => {
    if (err) {
      // A gateway check must never block: the caller asked for a silent check,
      // so a rejected ticket means continuing unauthenticated.
      if (opts.gateway) {
        this.pass();
      } else {
        this.fail({ message: err.message }, 401);
      }
      return;
    }
    if (req.session) {
      delete req.session[CASAuthentication.GATEWAY_SESSION_FLAG];
    }

    const profile = {
      provider: 'cas',
      id: user,
      user,
      attributes: attributes || {},
    };

    // With no verify callback the CAS profile itself becomes req.user.
    if (!this._verify) {
      this.success(profile);
      return;
    }

    const verified = (verifyErr, verifiedUser, info) => {
      if (verifyErr) {
        this.error(verifyErr);
      } else if (!verifiedUser) {
        this.fail(info);
      } else {
        this.success(verifiedUser, info);
      }
    };

    if (this._passReqToCallback) {
      this._verify(req, profile, verified);
    } else {
      this._verify(profile, verified);
    }
  });
};

module.exports = Strategy;
module.exports.Strategy = Strategy;
