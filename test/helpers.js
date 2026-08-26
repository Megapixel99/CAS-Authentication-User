'use strict';

const http = require('http');
const CASAuthentication = require('../index.js');

/**
 * A minimal stand-in for an Express request.
 */
function makeReq(overrides) {
  const req = {
    url: '/app',
    path: '/app',
    host: 'my-service-host.com',
    query: {},
    session: {},
  };
  Object.assign(req, overrides || {});
  // Give the session a destroy() that behaves like express-session's, which
  // removes req.session outright (session/session.js: `delete this.req.session`)
  // before calling the store. Anything that touches req.session afterwards has
  // to cope with it being gone, so the double must not paper over that.
  if (req.session && !req.session.destroy) {
    Object.defineProperty(req.session, 'destroy', {
      enumerable: false,
      configurable: true,
      value: function destroy(cb) {
        req.sessionDestroyed = true;
        delete req.session;
        if (cb) cb(null);
      },
    });
  }
  return req;
}

/**
 * A minimal stand-in for an Express response. `settled` resolves the first
 * time the response is completed, so async paths can be awaited.
 */
function makeRes() {
  const res = { redirects: [], statuses: [] };
  let settle;
  res.settled = new Promise((resolve) => { settle = resolve; });
  res.redirect = function redirect(location) {
    res.redirects.push(location);
    settle({ type: 'redirect', value: location });
  };
  res.sendStatus = function sendStatus(code) {
    res.statuses.push(code);
    settle({ type: 'status', value: code });
  };
  return res;
}

/**
 * Records calls to next(), and exposes a promise for the async paths.
 */
function makeNext() {
  const next = function next(err) {
    next.calls.push(err);
    next.settle({ type: 'next', value: err });
  };
  next.calls = [];
  next.settled = new Promise((resolve) => { next.settle = resolve; });
  return next;
}

/**
 * Starts a throwaway HTTP server that plays the part of a CAS server.
 * `responder(req)` returns a body string, or {status, body}.
 */
function startCasServer(responder) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      requests.push({ url: req.url, method: req.method, body, headers: req.headers });
      const out = responder(req, body) || '';
      const { status = 200, body: payload = out } = typeof out === 'object' ? out : {};
      res.writeHead(status, { 'Content-Type': 'text/xml' });
      res.end(typeof out === 'string' ? out : payload);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        requests,
        port: server.address().port,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/**
 * Builds a CASAuthentication instance pointed at a local fake CAS server. The
 * explicit port in cas_url is honoured by the constructor, so nothing needs
 * fixing up by hand.
 */
function casFor(port, options) {
  return new CASAuthentication(Object.assign({
    cas_url: `http://127.0.0.1:${port}/cas`,
    service_url: 'http://my-service-host.com',
  }, options || {}));
}

/**
 * index.js logs expected validation failures via console.error. Swallow that
 * during tests that deliberately provoke a failure. Returns a restore fn.
 */
function silenceErrors() {
  const original = console.error;
  console.error = () => {};
  return () => { console.error = original; };
}

/**
 * Runs a Passport strategy the way Passport itself does: shallow-copy the
 * instance, augment it with the outcome callbacks, then call authenticate().
 * Resolves with whichever outcome the strategy reached.
 */
function runStrategy(strategy, req, options) {
  return new Promise((resolve) => {
    const instance = Object.create(strategy);
    instance.success = (user, info) => resolve({ type: 'success', user, info });
    instance.fail = (challenge, status) => resolve({ type: 'fail', challenge, status });
    instance.redirect = (location, status) => resolve({ type: 'redirect', location, status });
    instance.pass = () => resolve({ type: 'pass' });
    instance.error = (err) => resolve({ type: 'error', err });
    instance.authenticate(req, options);
  });
}

/**
 * A logger double that records what the library reports, so a test can assert
 * on a diagnostic rather than swallowing it. Passed as the `logger` option.
 */
function collectingLogger() {
  const calls = [];
  return {
    calls,
    error: (...args) => { calls.push(args); },
    // The first argument is the only part a test wants to match on; the rest is
    // the Error itself.
    messages: () => calls.map((args) => (args[0] instanceof Error ? args[0].message : args[0])),
  };
}

module.exports = {
  makeReq,
  makeRes,
  makeNext,
  startCasServer,
  casFor,
  silenceErrors,
  collectingLogger,
  runStrategy,
  CASAuthentication,
};
