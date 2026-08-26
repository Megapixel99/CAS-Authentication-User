# CAS Authentication for Express

[![CI](https://github.com/Megapixel99/CAS-Authentication-User/actions/workflows/ci.yml/badge.svg)](https://github.com/Megapixel99/CAS-Authentication-User/actions/workflows/ci.yml)

Middleware and route handlers that authenticate an [Express](https://expressjs.com/) application against a [CAS](https://apereo.github.io/cas/development/protocol/CAS-Protocol.html) server.

This package is a fork of [cas-authentication](https://github.com/kayleecodes1/cas-authentication) by [kayleecodes1](https://github.com/kayleecodes1); see [Origins](#origins) for what came from there and what was added here.

All four protocol versions CAS defines are implemented, each with its own validation endpoint and its own response parser: 1.0 at `/validate`, 2.0 at `/serviceValidate`, 3.0 at `/p3/serviceValidate`, and SAML 1.1 at `/samlValidate`. The version is resolved once in the constructor (which assigns the endpoint and the parser together), so every path downstream of it is version-agnostic. `npm test` reports 224 tests across 14 files and requires no CAS deployment to run any of them, because the suite stands up a local HTTP server that plays the CAS role; two of those files drive the middleware through real Express, real [express-session](https://www.npmjs.com/package/express-session) and real [Passport](https://www.passportjs.org/) rather than through doubles.

There is one runtime dependency, [xml2js](https://www.npmjs.com/package/xml2js), which parses the CAS 2.0, 3.0 and SAML 1.1 responses. Though a Passport strategy ships with the package, `passport` itself is not a dependency of it.

**Write-up:** [What Maintaining a Forked npm Package Actually Buys](https://sethwheeler.dev/blog/forked-package-semver/) — a caret below 1.0.0 walls off the published fix, so `npm audit` reports "No fix available"; what it could not see was the open redirect this fork shipped for seven years while auditing clean.

## Requirements

A session middleware such as express-session has to be installed ahead of this middleware (ahead of it in the stack, not merely present in the project), since the authenticated username is kept on `req.session`. Every entry point checks for the session and throws an error naming express-session when it is absent, rather than failing several lines later on a property of `undefined`.

## Installation

```
$ npm install cas-authentication-user
```

## Setup

```javascript
let CASAuthentication = require('cas-authentication-user');

let cas = new CASAuthentication({
  cas_url            : 'https://my-cas-host.com/cas',
  service_url        : 'https://my-service-host.com',
  cas_version        : '3.0',
  renew              : false,
  is_dev_mode        : false,
  dev_mode_user      : '',
  dev_mode_info      : {},
  session_name       : 'cas_user',
  session_info       : 'cas_userinfo',
  destroy_session    : false,
  timeout            : 10000,
  regenerate_session : true
});
```

### Options

| Name | Type | Description | Default |
|:-----|:----:|:------------|:-------:|
| cas_url | _string_ | The URL of the CAS server. An explicit port is honoured; without one the port follows the protocol (80 for http, 443 for https). | _(required)_ |
| service_url | _string_ | The URL of the application, registered with the CAS server as a valid service. Set this to the origin only, with no path; see [Mounting on a sub-path](#mounting-on-a-sub-path). | _(required)_ |
| cas_version | _"1.0"\|"2.0"\|"3.0"\|"saml1.1"_ | The CAS protocol version. | _"3.0"_ |
| renew | _boolean_ | If true, an unauthenticated client has to log in to CAS whether or not a single sign-on session already exists. Takes precedence over a gateway check, as the CAS protocol requires. | _false_ |
| is_dev_mode | _boolean_ | If true, CAS is not contacted at all and the session variable is set to _dev_mode_user_. | _false_ |
| dev_mode_user | _string_ | The CAS user to authenticate as while dev mode is active. | _""_ |
| dev_mode_info | _Object_ | The CAS attributes to use while dev mode is active. | _{}_ |
| session_name | _string_ | The name of the session variable holding the CAS username once the client is authenticated. | _"cas_user"_ |
| session_info | _string_ | The name of the session variable holding the CAS attributes. A falsy value forwards no attributes, and the option is ignored under CAS 1.0, which cannot supply them. | _false_ |
| destroy_session | _boolean_ | If true, `logout` destroys the whole session; otherwise it deletes only the keys this library writes. | _false_ |
| timeout | _number_ | Milliseconds to wait for the CAS server to answer a ticket validation before giving up. A CAS server that accepts the connection and then never replies would otherwise hold the client's request open indefinitely, since `http.request` applies no timeout of its own. 0 waits forever. | _10000_ |
| regenerate_session | _boolean_ | If true, the session identifier is regenerated when a client authenticates, so a session fixed by an attacker beforehand does not carry over. Data already in the session is preserved; only the identifier changes. | _true_ |
| logger | _object_ | Where diagnostics are reported. Any object with an `error(...args)` method, which `console` and the common logging libraries all satisfy. See [Diagnostics](#diagnostics). | _console_ |

## Usage

```javascript
let app = require('express')();
let session = require('express-session');
let CASAuthentication = require('cas-authentication-user');

// A session is required, so install it first.
app.use(session({
  secret: 'super secret key',
  resave: false,
  saveUninitialized: true
}));

let cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com'
});

// Unauthenticated clients are sent to the CAS login and then back here.
app.get('/app', cas.bounce, ( req, res ) => {
  res.send( '<html><body>Hello!</body></html>' );
});

// Unauthenticated clients get a 401 instead of the JSON.
app.get('/api', cas.block, ( req, res ) => {
  res.json({ success: true });
});

// The CAS username, which is where a local user record would be looked up.
app.get('/api/user', cas.block, ( req, res ) => {
  res.json({ cas_user: req.session[cas.session_name] });
});

// userType starts as an empty string; populating it from your own records is
// left to the application.
app.get('/api/user-type', cas.block, ( req, res ) => {
  res.json({ cas_user_type: req.session.userType });
});

// A client already signed in elsewhere is authenticated without seeing a login
// page, and everyone else reaches the handler unauthenticated.
app.get('/', cas.gateway, ( req, res ) => {
  const user = req.session[cas.session_name];
  res.send(user ? `<html><body>Hello ${user}!</body></html>`
                : '<html><body>Hello stranger. <a href="/login">Sign in</a></body></html>');
});

// Once authenticated, the client goes to the returnTo query parameter.
app.get('/authenticate', cas.bounce_redirect);

// De-authenticates with the Express server, then redirects to the CAS logout.
app.get('/logout', cas.logout);

// Redirects to the CAS login.
app.get('/login', cas.login);
```

## The middleware

Three functions guard a route:

- `bounce`: an unauthenticated client is redirected to the CAS login page, and back to the page they asked for once CAS authenticates them.
- `block`: an unauthenticated client receives a 401 and the route handler does not run. This is the one for an endpoint answering XHR (a 302 to an HTML login page tells the caller nothing it can act on).
- `gateway`: CAS is asked whether the client already holds a single sign-on session, and a "no" is accepted rather than escalated into a login page.

Three more are route endpoints rather than guards:

- `bounce_redirect`: like `bounce`, except that an authenticated client is sent to the `returnTo` query parameter.
- `login`: redirects to the CAS login page.
- `logout`: clears the session keys this library writes (or destroys the whole session) and redirects to the CAS logout page.

## Gateway mode

`bounce` and `block` both force the question: log in, or be refused. Gateway mode is the third answer the CAS protocol allows, and it is what a page open to anonymous visitors needs, since it greets a signed-in user by name without turning everyone else away.

```javascript
app.get('/', cas.gateway, ( req, res ) => {
  if (req.session[cas.session_name]) {
    // Signed in elsewhere already, and no login page was shown to get here.
  } else {
    // No CAS session, and the request still arrived.
  }
});
```

Three things about it are worth knowing before it goes on a route.

**A client is checked once.** Without that, a visitor with no CAS session would be bounced to the CAS server on every request they made. The check is recorded twice: in the session under `CASAuthentication.GATEWAY_SESSION_FLAG` (`'cas_gateway_attempted'`), and as a `cas_gateway=1` parameter on the service URL handed to CAS (`CASAuthentication.GATEWAY_QUERY_PARAM`). The second copy is what makes the check terminate for a client whose session never persists (cookies blocked, or a crawler keeping no jar), which would otherwise redirect between the application and CAS until the browser gave up. `logout` clears the session flag, and deleting it yourself forces a fresh check.

**A gateway check never blocks.** A ticket that fails validation, a CAS server that cannot be reached, and one that times out all leave the request continuing unauthenticated rather than returning 401 (a spent ticket from a page refresh is the common case). `bounce` still answers 401 in the same situations, since a client who reached `bounce` did ask to log in.

**`renew` takes precedence over gateway**, which the CAS protocol requires, so a `gateway` route on an instance configured with `renew: true` behaves like `bounce`: CAS is asked for a real login every time, and abandoning the login form does not quietly turn the route anonymous.

### What gateway mode cannot do

CAS gives a service no way to tell "the client came back from a gateway check with no session" apart from "the client simply navigated here", so the marker described above is the only signal available. Two consequences follow from that, and both are deliberate.

A client with no usable session costs one CAS round trip per page view, because the marker covers only the return hop. That is bounded per request rather than per client, which is the price of not looping forever; if a lot of cookie-less traffic reaches gateway routes, crawlers in particular, expect those requests at the CAS server.

Anyone can put `?cas_gateway=1` in a link, which suppresses the check for that one request, so a user who would have been signed in transparently sees the page anonymously instead. Honouring the marker only in the absence of a session would reintroduce the redirect loop, since a session that never persists cannot be distinguished from one that does. The effect is a single anonymous render, as the pass-through deliberately records nothing and the next request checks again. Gateway mode is therefore the wrong tool where rendering anonymously is a security decision, and `block` or `bounce` is the right one.

## Passport strategy

A [Passport](https://www.passportjs.org/) strategy is available as a second entry point. It wraps the same ticket validation the middleware uses, so it covers CAS 1.0, 2.0, 3.0 and SAML 1.1 without reimplementing any of them.

```javascript
let passport = require('passport');
let CASStrategy = require('cas-authentication-user/strategy');

passport.use(new CASStrategy({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
}, ( profile, done ) => {
  // profile is { provider: 'cas', id, user, attributes }.
  User.findOne({ netid: profile.user }, done);
}));

app.get('/login', passport.authenticate('cas'));
```

Leaving the verify callback out makes the CAS profile itself `req.user`.

### Strategy options

Every option in the table above applies, plus these:

| Name | Type | Description | Default |
|:-----|:----:|:------------|:-------:|
| cas | _CASAuthentication_ | An existing instance to reuse rather than constructing one from these options. | _(none)_ |
| name | _string_ | The name Passport registers the strategy under. | _"cas"_ |
| passReqToCallback | _boolean_ | Pass `req` as the verify callback's first argument. | _false_ |

Passing `{ gateway: true }` to `passport.authenticate` performs a gateway check. The strategy calls `pass()` both when the client turns out to have no CAS session and when a returned ticket fails validation, so the request continues down the middleware chain either way, and it works with or without session support.

```javascript
app.get('/', passport.authenticate('cas', { gateway: true }), ( req, res ) => {
  res.send(req.user ? `Hello ${req.user.user}!` : 'Hello stranger.');
});
```

## TypeScript

Declarations ship with the package for both entry points. They describe the middleware in terms of Express's own `RequestHandler`, so a TypeScript project also needs `@types/express`, which is declared as an optional peer dependency and is almost certainly present already in an Express application written in TypeScript.

```
$ npm install --save-dev @types/express
```

```typescript
import CASAuthentication = require('cas-authentication-user');
import CASStrategy = require('cas-authentication-user/strategy');

const cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
  cas_version: '3.0',
});

app.get('/app', cas.bounce, ( req, res ) => res.send('Hello!'));
```

Typed access to the session keys comes from augmenting `express-session`:

```typescript
declare module 'express-session' {
  interface SessionData {
    cas_user?: string;
    cas_userinfo?: CASAuthentication.CASAttributes;
    cas_return_to?: string;
    userType?: string;
    cas_gateway_attempted?: boolean;
  }
}
```

Attribute names released under CAS 2.0 and 3.0 arrive lower-cased, because they arrive as XML tags and the parser normalizes tag names; a CAS `displayName` therefore reaches the session as `displayname`. SAML 1.1 preserves the case as sent, since it carries the name in an XML attribute instead.

Attribute values are typed as `CASAttributeValue`, which is deliberately wider than `string`: a nested CAS attribute comes through as an object, and a SAML 1.1 value carrying no `xsi:type` comes through as `undefined`. Narrow before use.

```typescript
const raw = req.session.cas_userinfo?.memberOf;
const groups = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
```

## Behaviour worth knowing

### The returnTo parameter

`bounce_redirect` and `login` both accept a `returnTo` query parameter naming where to send the client once they are authenticated. That value arrives from the client, so only a same-origin path is accepted: it has to begin with a single `/`. An absolute URL, a protocol-relative `//host` path, the `/\host` variant some browsers normalize into one, and a scheme such as `javascript:` are all refused, and the client goes to the path they requested instead.

The restriction is not tidiness. Without it, an attacker could hand a victim a link that logs them in at the genuine CAS server and then lands them on a site of the attacker's choosing, which is a phishing flow with a real login in the middle of it. Versions before 0.3.0 redirected to whatever `returnTo` contained (which is why 0.3.0 is a minor bump rather than a patch).

### The request path

`returnTo` is not the only client-controlled value that decides where a redirect lands. The request path does too: `bounce_redirect` falls back to it when no `returnTo` is supplied, and it forms the service URL sent to CAS. A path is not automatically same-origin, because `//host` is protocol-relative and `/\host` is the variant browsers normalize into one.

Request URLs are parsed with the WHATWG `URL` API against a base that cannot exist, and a path that resolves away from that base is replaced with `/`. Node's legacy `url.parse` reported both forms above as a *pathname*, so a client sent to `/\evil.example.com` on a `bounce_redirect` route was redirected off-site — with no CAS round trip involved, since an already authenticated client never reaches one. Node documents that parser as [DEP0169](https://nodejs.org/api/deprecations.html#DEP0169), noting that CVEs are not issued against it.

### Query strings and the login round trip

The service URL sent to CAS is the request path without its query string, so page parameters are never handed to the CAS server (nor written into its access logs, which is where a `?token=` would otherwise come to rest). The trade-off is that a client sent to CAS from `/search?q=cats` returns to `/search`, so pass `returnTo` where the destination matters:

```javascript
app.get('/search', cas.bounce, handler);   // returns to /search
// A link that keeps its parameters across the round trip:
// /authenticate?returnTo=%2Fsearch%3Fq%3Dcats
```

### Mounting on a sub-path

The service URL is built from `req.originalUrl`, so mounting inside a router works as expected:

```javascript
const router = require('express').Router();
router.get('/page', cas.bounce, ( req, res ) => res.send('Hello!'));
app.use('/portal', router);
// CAS is sent service=https://my-service-host.com/portal/page
```

Set `service_url` to the application's origin and leave the mount prefix out of it. Versions before 0.3.0 built the service URL from the mount-relative path, which sent CAS a path with the prefix missing; if that was compensated for by putting the prefix into `service_url`, remove it.

### Diagnostics

Nothing this library reports is thrown. A ticket CAS rejects, a CAS server that cannot be reached, a session store that fails to regenerate — each of these is a condition the request has already recovered from by the time it is reported, so raising it would turn a handled case into an unhandled one. They are written to `logger.error` instead.

The consequence is that with the default `console` these lines land on stderr, separate from wherever the application's own logs go, and in a container they are easy to lose. Pass a `logger` to put them in the same place as everything else:

```javascript
let cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
  logger: pino({ name: 'cas' })   // or bunyan, winston, or your own { error() }
});
```

Any object with an `error(...args)` method will do. The constructor throws if it is given anything else, since a logger that silently fails to log is worse than none.

### Validation failures

A ticket CAS rejects, a CAS server that cannot be reached, one that times out, and one that reports success without a username are treated alike: `bounce` and `block` answer 401, and `gateway` continues unauthenticated.

The last of those matters more than it looks. An empty username would be stored in the session as `''`, which is falsy (and so indistinguishable from absent), so the client would look unauthenticated on the very next request and be sent back to CAS, and then again, indefinitely. It is refused instead.

### Sessions on login and logout

The session identifier is regenerated when a client authenticates. Without that, an attacker able to plant a session cookie on a victim before they log in would still hold a valid handle on the authenticated session afterwards (session fixation). Anything the application had already put in the session is copied across, so only the identifier changes. Setting `regenerate_session: false` switches the behaviour off.

`logout` removes every session key this library writes: the CAS username, the CAS attributes, `cas_return_to`, `userType`, and the gateway flag. `userType` is the one that matters most, since it is what applications tend to authorise on, and leaving the previous user's value behind while their username is gone invites acting on a privilege that is no longer held. With `destroy_session: true` the whole session goes instead.

## Tests

```
$ npm test
```

That runs the suite on [Node's built-in test runner](https://nodejs.org/api/test.html) and then type-checks the declarations against a file written the way a consumer would write one. No CAS server is needed, since the tests stand up a local HTTP server that answers as one; `test/session-integration.test.js` and `test/passport-integration.test.js` go further and drive the middleware through real Express, real express-session and real Passport over real HTTP (no doubles for any of the three), which is what catches the class of bug a hand-written session double hides.

CI runs both commands on Node 20, 22, 24 and 26. A second job covers what no test can: the `files` field decides what a consumer actually receives, so that job packs the tarball, installs it into an empty project with `--omit=dev`, and checks that both entry points load with xml2js as the only dependency present. Of those four versions only 22, 24 and 26 are still in support (Node 20 reached end of life on 2026-04-30); 20 is there because the institutions this package is aimed at upgrade slowly, and knowing it still works is worth a job.

## Upgrading to 0.3.0

Five changes affect behaviour an existing deployment may depend on.

- The service URL is built from `req.originalUrl`, so a router mount prefix is included in it. Remove the prefix from `service_url` if it was put there to compensate.
- `returnTo` accepts same-origin paths only.
- Ticket validation gives up after 10 seconds by default (previously there was no timeout at all). Set `timeout: 0` to wait indefinitely as before.
- The session identifier is regenerated on login. Set `regenerate_session: false` for the previous behaviour.
- `cas_port` honours an explicit port in `cas_url` rather than always taking 80 or 443 from the protocol, so a CAS server on a non-standard port is now reached at the port it was configured with.

## Origins

This package began in 2019 as a fork of [cas-authentication](https://github.com/kayleecodes1/cas-authentication) by [kayleecodes1](https://github.com/kayleecodes1), whose last release was 0.0.8 in November 2015. That library is MIT licensed and this one keeps the same license.

What came from there is most of the shape this README describes. The `bounce`, `block`, `bounce_redirect` and `logout` entry points are theirs, as are their semantics and the choice to answer 401 from `block` rather than redirect. So are ten of the options in the table above (`cas_url`, `cas_version`, `service_url`, `renew`, `is_dev_mode`, `dev_mode_user`, `dev_mode_info`, `session_name`, `session_info` and `destroy_session`), the dev-mode design, and support for all four CAS protocol versions with their separate endpoints and response parsers. The structure that makes the rest of the code version-agnostic, resolving the endpoint and the parser together once in the constructor, is theirs too.

Added here: gateway mode, the `login` endpoint, the Passport strategy, the TypeScript declarations, the test suite and CI, the `timeout` and `regenerate_session` options, and the 0.3.0 behaviour changes listed under [Upgrading to 0.3.0](#upgrading-to-030). Two of those are fixes to inherited behaviour rather than new features: the unvalidated `returnTo` redirect and the absence of session regeneration on login both came from upstream and were carried here until 0.3.0.

## License

MIT. See [LICENSE](LICENSE).
