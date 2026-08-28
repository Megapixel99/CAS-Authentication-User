# CAS Authentication for Express

[![npm version](https://img.shields.io/npm/v/cas-authentication-user.svg)](https://www.npmjs.com/package/cas-authentication-user)
[![downloads](https://img.shields.io/npm/dm/cas-authentication-user.svg)](https://www.npmjs.com/package/cas-authentication-user)
[![unpacked size](https://img.shields.io/npm/unpacked-size/cas-authentication-user.svg)](https://www.npmjs.com/package/cas-authentication-user?activeTab=code)
[![node](https://img.shields.io/node/v/cas-authentication-user.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/cas-authentication-user.svg)](LICENSE)
[![CI](https://github.com/Megapixel99/CAS-Authentication-User/actions/workflows/ci.yml/badge.svg)](https://github.com/Megapixel99/CAS-Authentication-User/actions/workflows/ci.yml)

Middleware and route handlers that authenticate an [Express](https://expressjs.com/) application against a [CAS](https://apereo.github.io/cas/development/protocol/CAS-Protocol.html) server.

This package is a fork of [cas-authentication](https://github.com/kayleecodes1/cas-authentication) by [kayleecodes1](https://github.com/kayleecodes1); see [Origins](#origins) for what came from there and what was added here.

All four protocol versions CAS defines are implemented, each with its own validation endpoint and its own response parser: 1.0 at `/validate`, 2.0 at `/serviceValidate`, 3.0 at `/p3/serviceValidate`, and SAML 1.1 at `/samlValidate`. The version is resolved once in the constructor (which assigns the endpoint and the parser together), so every path downstream of it is version-agnostic. `npm test` reports 242 tests across 16 files and requires no CAS deployment to run any of them, because the suite stands up a local HTTP server that plays the CAS role; two of those files drive the middleware through real Express, real [express-session](https://www.npmjs.com/package/express-session) and real [Passport](https://www.passportjs.org/) rather than through doubles.

There is one runtime dependency, [xml2js](https://www.npmjs.com/package/xml2js), which parses the CAS 2.0, 3.0 and SAML 1.1 responses. Though a Passport strategy ships with the package, `passport` itself is not a dependency of it.

**Write-up:** [What Maintaining a Forked npm Package Actually Buys](https://sethwheeler.dev/blog/forked-package-semver/) — a caret below 1.0.0 walls off the published fix, so `npm audit` reports "No fix available"; what it could not see was the pair of open redirects this fork shipped for seven years while auditing clean. Both date from the first publish in 2019, and fixing one did nothing for the other: `returnTo` was validated in 0.3.0, while the request path reaches `res.redirect` without passing through `returnTo` at all and went unfixed until 0.4.0, eight days later.

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
  regenerate_session : true,
  logger             : console,
  manage_user_type   : true
});
```

### Options

| Name | Type | Description | Default |
|:-----|:----:|:------------|:-------:|
| cas_url | _string_ | The URL of the CAS server. An explicit port is honoured; without one the port follows the protocol (80 for http, 443 for https). | _(required)_ |
| service_url | _string_ | The URL of the application, registered with the CAS server as a valid service. Set this to the origin only, with no path; see [Mounting on a sub-path](#mounting-on-a-sub-path). | _(required)_ |
| cas_version | _"1.0"\|"2.0"\|"3.0"\|"saml1.1"_ | The CAS protocol version. | _"3.0"_ |
| renew | _boolean_ | If true, an unauthenticated client has to log in to CAS whether or not a single sign-on session already exists. Takes precedence over a gateway check, as the CAS protocol requires. | _false_ |
| is_dev_mode | _boolean_ | If true, CAS is not contacted at all and the session variable is set to _dev_mode_user_. Every request is authenticated as that user, so this is announced on the logger at construction to make a deployment that reaches production with it on visible. | _false_ |
| dev_mode_user | _string_ | The CAS user to authenticate as while dev mode is active. Required when `is_dev_mode` is set: a blank username is the one value the library refuses from a real CAS server, since it leaves the client authenticated to the middleware and anonymous to the application. | _""_ |
| dev_mode_info | _Object_ | The CAS attributes to use while dev mode is active. | _{}_ |
| session_name | _string_ | The name of the session variable holding the CAS username once the client is authenticated. | _"cas_user"_ |
| session_info | _string_ | The name of the session variable holding the CAS attributes. A falsy value forwards no attributes, and the option is ignored under CAS 1.0, which cannot supply them. | _false_ |
| destroy_session | _boolean_ | If true, `logout` destroys the whole session; otherwise it deletes only the keys this library writes. | _false_ |
| timeout | _number_ | Milliseconds allowed for a ticket validation to complete before it is abandoned. A deadline for the whole call, not an idle timer, so a CAS server that trickles bytes indefinitely is cut off at the budget rather than holding the client's request open. 0 waits forever. | _10000_ |
| max_response_bytes | _number_ | Largest CAS response body to buffer, in bytes. A response past it fails the validation instead of being read into memory. 0 disables the check. | _1048576_ |
| regenerate_session | _boolean_ | If true, the session identifier is regenerated when a client authenticates, so a session fixed by an attacker beforehand does not carry over. Data already in the session is preserved; only the identifier changes. | _true_ |
| logger | _object_ | Where diagnostics are reported. Any object with an `error(...args)` method, which `console` and the common logging libraries all satisfy. See [Diagnostics](#diagnostics). | _console_ |
| manage_user_type | _boolean_ | Whether this library writes and clears `req.session.userType`. Deprecated; see [The userType session key](#the-usertype-session-key). | _true_ |

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
// left to the application. Deprecated - see The userType session key.
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

// Once authenticated, the client goes to the returnTo query parameter, or to
// the site root if there is none.
app.get('/authenticate', cas.bounce_redirect);

// De-authenticates with the Express server, then redirects to the CAS logout.
app.get('/logout', cas.logout);

// Starts a login, and completes the one CAS sends back to this route.
app.get('/login', cas.login);
```

## The middleware

Three functions guard a route:

- `bounce`: an unauthenticated client is redirected to the CAS login page, and back to the page they asked for once CAS authenticates them.
- `block`: an unauthenticated client receives a 401 and the route handler does not run. This is the one for an endpoint answering XHR (a 302 to an HTML login page tells the caller nothing it can act on).
- `gateway`: CAS is asked whether the client already holds a single sign-on session, and a "no" is accepted rather than escalated into a login page.

Three more are route endpoints rather than guards:

- `bounce_redirect`: like `bounce`, except that an authenticated client is sent to the `returnTo` query parameter. Without a usable `returnTo` there is no destination to send them to, so they go to the site root; the request path is not a fallback, because that is the route they are already on. See [Where an authenticated client lands](#where-an-authenticated-client-lands).
- `login`: sends an unauthenticated client to the CAS login page, and completes the round trip when CAS returns them to this route with a ticket. A client who is already authenticated is sent onward rather than back to CAS.
- `logout`: clears the session keys this library writes (or destroys the whole session), calls `req.logout()` when Passport is present, and redirects to the CAS logout page.

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
    cas_gateway_attempted?: boolean;
    // Written by this library only while manage_user_type is on, which is
    // deprecated; see The userType session key.
    userType?: string;
  }
}
```

Attribute names released under CAS 2.0 and 3.0 arrive lower-cased, because they arrive as XML tags and the parser normalizes tag names; a CAS `displayName` therefore reaches the session as `displayname`. SAML 1.1 preserves the case as sent, since it carries the name in an XML attribute instead.

Attribute values are typed as `CASAttributeValue`, which is deliberately wider than `string`: a nested CAS attribute comes through as an object, and a SAML 1.1 `<Attribute/>` with no value at all comes through as `undefined`. Narrow before use.

```typescript
const raw = req.session.cas_userinfo?.memberOf;
const groups = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
```

## Behaviour worth knowing

### The returnTo parameter

`bounce_redirect` and `login` both accept a `returnTo` query parameter naming where to send the client once they are authenticated. That value arrives from the client, so only a same-origin path is accepted: it has to begin with a single `/`. An absolute URL, a protocol-relative `//host` path, the `/\host` variant some browsers normalize into one, and a scheme such as `javascript:` are all refused, and the client goes to the site root instead.

A fragment is kept for the client and withheld from CAS: `returnTo=/reports#summary` sends `https://app.example.com/reports` as the service URL and redirects to `/reports#summary` at the end. Sending the fragment to CAS would bring the ticket back *inside* it, where the application cannot read it.

The restriction is not tidiness. Without it, an attacker could hand a victim a link that logs them in at the genuine CAS server and then lands them on a site of the attacker's choosing, which is a phishing flow with a real login in the middle of it. Versions before 0.3.0 redirected to whatever `returnTo` contained (which is why 0.3.0 is a minor bump rather than a patch).

### Where an authenticated client lands

`bounce_redirect` and `login` are meant to be mounted at a login route, which makes that route the one place they must never send anybody. An absent or rejected `returnTo` used to fall back to "where the client already is": the same URL, in the same state, which the browser followed straight back into the same handler until it gave up with a redirect-loop error. That happened on a plain `GET /login` with no query string at all, and after a completely successful CAS login. The fallback is now the site root, and a `bounce_redirect` mounted at the root passes the request through to the application instead of redirecting.

### The request path

`returnTo` is not the only client-controlled value that decides where a redirect lands. The request path does too, since it forms the service URL sent to CAS. A path is not automatically same-origin, because `//host` is protocol-relative and `/\host` is the variant browsers normalize into one, and because a path containing `..` can be *normalized into* one, which is a different problem with the same ending.

Request URLs are parsed with the WHATWG `URL` API against a base that cannot exist, and a path that resolves away from that base is replaced with `/`. Node's legacy `url.parse` reported both forms above as a *pathname*, so a client sent to `/\bad.example.com` on a `bounce_redirect` route was redirected off-site — with no CAS round trip involved, since an already authenticated client never reaches one. Node documents that parser as [DEP0169](https://nodejs.org/api/deprecations.html#dep0169-insecure-urlparse), noting that CVEs are not issued against it.

Reading the origin back is necessary and, until 0.5.0, was not sufficient. `//bad.example.com` does resolve to another origin and was caught; `/..//bad.example.com` does not. The dot segment is resolved away, leaving *this* origin with a pathname of `//bad.example.com`, which is protocol-relative again the moment it reaches a `Location` header and which the origin check never sees. `/%2e%2e//host`, `/a/b/../../..//host` and `/../\host` all normalize to the same thing, the last of them manufacturing the exact `/\host` shape the `returnTo` check rejects on sight. The pathname is now checked alongside the origin. This is the third instance of this bug in this package, after `returnTo` in 0.3.0 and the request path in 0.4.0, and the first two fixes could not have caught it: both inspect the value as it arrives, while this one is produced by the parser itself.

### Query strings and the login round trip

The service URL sent to CAS is the request path without its query string, so page parameters are never handed to the CAS server (nor written into its access logs, which is where a `?token=` would otherwise come to rest). The client's own query string is remembered in the session and restored at the end of the round trip, so a visitor sent to CAS from `/search?q=cats` lands back on `/search?q=cats`. Only a client whose session does not survive the round trip loses it, and then `returnTo` carries the destination explicitly:

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

### The userType session key

`req.session.userType` is not part of the CAS protocol, and nothing in this library reads it. The library blanks it when it sends a client to CAS and deletes it on logout; populating it is left to the application. (It is not blanked on the paths that never reach CAS: a `block` route answering 401, or a gateway check passing an anonymous client through.) That is a library reaching into an application's own session state, and it is deprecated.

```javascript
let cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
  manage_user_type: false     // the only behaviour in 1.0
});
```

The blanking is not pointless, which is why the field cannot simply stop being touched. `userType` is what applications tend to authorise on, so a value left over from the previous user, sitting beside a username that has been cleared, invites acting on a privilege that is no longer held. **An application that opts out takes that on:** clear the key on logout, or set `destroy_session: true` and let the whole session go. `CASAuthentication.USER_TYPE_SESSION_KEY` is exported so the same key can be used.

The default stays `true` until 1.0, so nothing changes for an existing deployment that has not asked for it.

### Validating a ticket on your own

`validateTicket` is ticket validation with no request, no session and no callback — the protocol selection, the HTTP call and the XML parsing, and nothing else. It is what the Passport strategy is built on, and what to build on for any other front end:

```javascript
const { user, attributes } = await cas.validateTicket({
  ticket: req.query.ticket,
  service: 'https://my-service-host.com/callback'
});
```

The `service` value has to be the exact string the ticket was issued for, or CAS will reject it. A failed validation rejects rather than resolving with an empty user, so it cannot be missed by forgetting to check.

The older callback form remains, and now also returns a promise when called without a callback:

```javascript
cas._validateTicket({ ticket, service }, (err, user, attributes) => { /* ... */ });
```

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

`logout` removes every session key this library writes: the CAS username, the CAS attributes, `cas_return_to`, the gateway flag, and — while `manage_user_type` is on — `userType`. That last one matters most, since it is what applications tend to authorise on, and leaving the previous user's value behind while their username is gone invites acting on a privilege that is no longer held; an application that has [opted out](#the-usertype-session-key) clears it itself. With `destroy_session: true` the whole session goes instead.

It also calls `req.logout()` when Passport has installed one, since Passport keeps the authenticated user under a session key this library does not own. Without that step a client who signed in through the bundled strategy was shown the CAS logout page and stayed signed in to the application.

A store that fails to write the cleared session, or to destroy it, is reported through `next(err)` rather than answered with the redirect to CAS: a logout that could not be persisted has not happened, and saying so is better than a page that claims otherwise.

### Known limitations

These are real, reproduced, and not fixed here, either because the CAS protocol leaves no room to fix them or because the fix belongs in the application.

- **A ticket is not bound to the login that started it.** CAS has no `state` parameter, so nothing ties a `?ticket=` arriving at the application to a login this browser began. Anyone who obtains a ticket for the service can send a victim's browser to a URL carrying it and log that browser in as themselves: login CSRF, whose payoff is the victim acting in the attacker's account rather than the reverse.
- **One destination per session.** The post-login destination lives in a single session key, so two tabs authenticating at once can send the user to the page the other tab asked for. Passing `returnTo` explicitly does not help: the last write wins.
- **A `returnTo` is checked for origin, not for reachability.** A path that no route serves, or one that is served by a route with no CAS middleware on it, is accepted; in the second case the ticket arrives somewhere nothing validates it, and the client lands anonymous. Point `returnTo` at a guarded route.
- **A client whose cookies never persist cannot complete a login.** `bounce` will send them to CAS on every request, since a session is what a login produces. Gateway mode is the bounded case, and is bounded deliberately: one CAS round trip per page view, never a loop.
- **Data an attacker put in a session before login survives the regeneration.** The session id rotates, which is what stops session fixation, but application keys are copied to the new session, so a value planted beforehand is still there afterwards. An application that reads its own session keys as trusted input should clear them on login.
- **A gateway check is made once per session.** A client who signs in at CAS after being checked is not noticed again until the gateway flag is cleared or the session ends.
- **A spent ticket in the address bar is answered with a bare 401.** A `?ticket=` that CAS has already consumed (reached by a refresh, or by pressing Back after logging out) fails validation on a `bounce` route, and `bounce` answers a failed validation with 401 rather than starting a fresh login. The client sees an unstyled error page with no way forward but editing the URL.
- **An already authenticated client keeps an unspent ticket in the address bar.** The session is checked before the query string, so a `?ticket=` on a request from a client who is already logged in is never consumed, and stays in history, in `Referer` and in any proxy log, valid because nothing has redeemed it.
- **A reverse proxy that rewrites the path cannot be configured.** `service_url` is the only knob, and it has to be both the origin the browser sees and the prefix the application is mounted under. With `proxy_pass http://app/` stripping a `/portal` prefix those two differ, and there is no `base_path` option to separate them. Proxy the prefix through unchanged instead.
- **`manage_user_type: false` leaves `userType` to survive a login.** The application owns the key in that mode, and session regeneration copies it to the new session, so the mechanism that looks like it clears the slate is what carries the previous user's value across. Clear it on login, or set `destroy_session: true`.
- **The Passport strategy uses a subset of the options.** It builds a `CASAuthentication` from whatever it is given, but only the CAS-facing options reach the protocol; `is_dev_mode` in particular does nothing there, and a `{ gateway: true }` check still needs a session middleware, or `{ session: false }`, because Passport establishes the login itself.
- **The strategy has no `callbackURL`.** The route that starts the flow is the route CAS returns to, so `passport.authenticate('cas')` has to be mounted on both. A `callbackURL` passed to the constructor is accepted and ignored.
- **The strategy redirects an XHR to the CAS login page.** Passport's `redirect()` is a 302 to a cross-origin HTML page, which a `fetch` caller cannot act on, and neither a custom callback nor `failureRedirect` converts it into a 401. The core middleware's `block` is the entry point for endpoints answering XHR.
- **`{ cas: instance }` is matched with `instanceof`.** Two copies of this package in one dependency tree (a transitive one alongside a direct one) produce two distinct constructors, so an instance built from the other copy fails the check and is silently replaced by a new one built from the same options.

## Tests

```
$ npm test
```

That runs the suite on [Node's built-in test runner](https://nodejs.org/api/test.html) and then type-checks the declarations against a file written the way a consumer would write one. No CAS server is needed, since the tests stand up a local HTTP server that answers as one; `test/session-integration.test.js` and `test/passport-integration.test.js` go further and drive the middleware through real Express, real express-session and real Passport over real HTTP (no doubles for any of the three), which is what catches the class of bug a hand-written session double hides.

CI runs both commands on Node 20, 22, 24 and 26. A second job covers what no test can: the `files` field decides what a consumer actually receives, so that job packs the tarball, installs it into an empty project with `--omit=dev`, and checks that both entry points load with xml2js as the only dependency present. Of those four versions only 22, 24 and 26 are still in support (Node 20 reached end of life on 2026-04-30); 20 is there because the institutions this package is aimed at upgrade slowly, and knowing it still works is worth a job.

## Upgrading to 0.5.0

Two changes are security fixes, and several fix loops that a browser reports to the user as a broken site.

- **A request path that *normalizes* to another origin no longer reaches `res.redirect`.** `/..//bad.example.com` resolves its dot segment away and leaves this origin with a pathname of `//bad.example.com`, which is protocol-relative once written into a `Location` header. The origin check added in 0.4.0 never saw it. The third instance of this bug in this package; see [The request path](#the-request-path).
- **The ticket and host interpolated into the SAML 1.1 SOAP request are escaped.** Both were written into the XML raw, and the ticket arrives from the client's query string.

Behaviour that changes, in rough order of how likely you are to notice:

- **`bounce_redirect` sends a client with no usable `returnTo` to the site root**, where it used to send them to the URL they were already on: a redirect to itself, which browsers follow until they give up. Mounted at the site root it now calls `next()` instead. See [Where an authenticated client lands](#where-an-authenticated-client-lands).
- **`login` is a complete login endpoint rather than an unconditional redirect to CAS.** Mounted as `app.get('/login', cas.login)`, as the README has always shown, it now validates the ticket CAS returns to that route and sends an already-authenticated client onward. Previously each hop bounced back to CAS and cost a fresh service ticket, for ever.
- **A gateway check keeps the visitor's query string** across the round trip, and keeps its own `cas_gateway` marker on the redirect that completes a ticket. Without the marker, a client whose session does not persist was sent to CAS on every single request.
- **`timeout` is a deadline for the whole validation**, not a socket-inactivity timer. A CAS server trickling bytes used to reset the timer indefinitely.
- **`logout` waits for `session.destroy()` and reports a store failure** through `next(err)` instead of redirecting as though the logout had succeeded. It also calls `req.logout()` when Passport is present, without which a client who signed in through the bundled strategy stayed signed in.
- **A login whose session cannot be saved fails** through `next(err)` rather than redirecting the client into a loop with nothing in the log.
- **Configuration that could not work is now refused at construction**: a `cas_url` or `service_url` whose scheme is not http or https, `is_dev_mode` without a `dev_mode_user`, and the `timeout` values (`null`, `false`, `[]`) that `Number()` quietly turned into "wait for ever". A trailing slash on either URL is trimmed rather than producing a doubled slash. Dev mode announces itself on the logger.
- **A CAS response is refused past `max_response_bytes`** (1 MiB by default) instead of being buffered without limit.
- **SAML 1.1 no longer fails a valid login over the shape of its attributes**: a success with no `<AttributeStatement>`, and an `<Attribute/>` with no value, both used to throw and be reported as failed authentication. An `<AttributeValue>` with no `xsi:type` now yields its text rather than `undefined`.
- **A username that arrives as an XML element with attributes is read as text.** `<cas:user format="upn">casuser</cas:user>` used to reach the session as `[object Object]`.
- **An exception thrown after a successful validation reaches Express**, rather than being caught by the response parser, reported as a bad CAS response, and dropped, which left the request with no response at all. In the Passport strategy a verify callback that throws now reaches `error()`.
- **A CAS server answering with an error status is reported as such**, rather than logged as the CAS server rejecting the ticket.

## Upgrading to 0.4.0

One change affects behaviour, and it is a security fix.

- **A request path that resolves to another origin no longer reaches `res.redirect`.** Request URLs are parsed with the WHATWG `URL` API rather than Node's deprecated `url.parse`, which reported `//host` and the `/\host` variant browsers normalize into it as a *pathname*. A client sent to `/\bad.example.com` on a `bounce_redirect` route was redirected off-site; such a path now resolves to `/`. This is a different input from the `returnTo` redirect fixed in 0.3.0 — `returnTo` was validated, the request path was not — and it needed no CAS round trip, since an already authenticated client is redirected before one happens. See [The request path](#the-request-path).

Nothing else is a breaking change. Three additions are worth knowing about:

- `logger` sends this library's diagnostics wherever the application's own logs go. Defaults to `console`, as before. See [Diagnostics](#diagnostics).
- `validateTicket` is ticket validation as a promise. The callback form is unchanged. See [Validating a ticket on your own](#validating-a-ticket-on-your-own).
- `manage_user_type: false` stops this library from writing `req.session.userType`. Managing that key is deprecated and the opt-out becomes the only behaviour in 1.0. See [The userType session key](#the-usertype-session-key).

`engines` now declares Node >= 20, matching the versions CI covers. npm reports this as a warning rather than refusing to install.

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

Added here: gateway mode, the `login` endpoint, the Passport strategy, the TypeScript declarations, the test suite and CI, the `timeout`, `regenerate_session`, `logger` and `manage_user_type` options, the promise form of ticket validation, and the behaviour changes listed under [Upgrading to 0.3.0](#upgrading-to-030) and [Upgrading to 0.4.0](#upgrading-to-040).

Three of those are fixes to inherited behaviour rather than new features. The unvalidated `returnTo` redirect and the absence of session regeneration on login both came from upstream and were carried here until 0.3.0. The second open redirect, through the request path rather than `returnTo`, was carried until 0.4.0. `userType` is inherited too, and is on its way out for the opposite reason: it is not a defect, just a key this library has no business writing into an application's session.

## License

MIT. See [LICENSE](LICENSE).
