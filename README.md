# Express CAS Authentication

This is a CAS authentication library designed to be used with an Express server.

It provides three middleware functions for controlling access to routes:

- `bounce`: Redirects an unauthenticated client to the CAS login page and then back to the requested page.
- `block`: Completely denies access to an unauthenticated client and returns a 401 response.
- `gateway`: Silently checks whether the client already has a CAS single sign-on session. If they do, they are authenticated transparently; if they do not, the request continues unauthenticated instead of being shown a login page.

It also provides two route endpoint functions:

- `bounce_redirect`: Acts just like `bounce` but once the client is authenticated they will be redirected to the provided _returnTo_ query parameter.
- `logout`: De-authenticates the client with the Express server and then redirects them to the CAS logout page.

## Installation

```
$ npm install cas-authentication-user
```

## Setup

javascript:
```javascript
let CASAuthentication = require('cas-authentication-user');

let cas = new CASAuthentication({
  cas_url         : 'https://my-cas-host.com/cas',
  service_url     : 'https://my-service-host.com',
  cas_version     : '3.0',
  renew           : false,
  is_dev_mode     : false,
  dev_mode_user   : '',
  dev_mode_info   : {},
  session_name    : 'cas_user',
  session_info    : 'cas_userinfo',
  destroy_session : false
});
```

### Options

| Name | Type | Description | Default |
|:-----|:----:|:------------|:-------:|
| cas_url | _string_ | The URL of the CAS server. | _(required)_ |
| service_url | _string_ | The URL of the application which is registered with the CAS server as a valid service. | _(required)_ |
| cas_version | _"1.0"\|"2.0\|"3.0"\|"saml1.1"_ | The CAS protocol version. | _"3.0"_ |
| renew | _boolean_ | If true, an unauthenticated client will be required to login to the CAS system regardless of whether a single sign-on session exists. | _false_ |
| is_dev_mode | _boolean_ | If true, no CAS authentication will be used and the session CAS variable will be set to whatever user is specified as _dev_mode_user_. | _false_ |
| dev_mode_user | _string_ | The CAS user to use if dev mode is active. | _""_ |
| dev_mode_info | _Object_ | The CAS user information to use if dev mode is active. | _{}_ |
| session_name | _string_ | The name of the session variable that will store the CAS user once they are authenticated. | _"cas_user"_ |
| session_info | _string_ | The name of the session variable that will store the CAS user information once they are authenticated. If set to false (or something that evaluates as false), the additional information supplied by the CAS will not be forwarded. This will not work with CAS 1.0, as it does not support additional user information. | _false_ |
| destroy_session | _boolean_ | If true, the logout function will destroy the entire session upon CAS logout. Otherwise, it will only delete the session variable storing the CAS user. | _false_ |
| timeout | _number_ | Milliseconds to wait for the CAS server to answer a ticket validation request before giving up. A CAS server that accepts the connection and then never replies would otherwise hold the client's request open indefinitely. Set to 0 to wait forever. | _10000_ |

## Usage

javascript:
```javascript
let app = require('express')();
let session = require('express-session');
let CASAuthentication = require('cas-authentication-user');

// Set up an Express session, which is required for CASAuthentication.
app.use(session({
  secret: 'super secret key',
  resave: false,
  saveUninitialized: true
}));

// Create a new instance of CASAuthentication.
let cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com'
});

// Unauthenticated clients will be redirected to the CAS login and then back to
// this route once authenticated.
app.get('/app', cas.bounce, ( req, res ) => {
  res.send( '<html><body>Hello!</body></html>' );
});

// All clients will receive a 401 Unauthorized response instead of
// the JSON data.
app.get('/api', cas.block, ( req, res ) => {
  res.json({ success: true });
});

// An example of accessing the CAS user session variable. This could be used to
// retrieve your own local user records based on authenticated CAS username.
app.get('/api/user', cas.block, ( req, res ) => {
  res.json({ cas_user: req.session[cas.session_name] });
});

// An example of accessing the CAS userType session variable. userType by default is an empty
// string, so you will have to retrieve your own local user records and set the variable yourself.
app.get('/api/user', cas.block, ( req, res ) => {
  res.json({ cas_user_type: req.session.userType });
});

// Clients who already have a CAS single sign-on session are authenticated
// transparently. Everyone else reaches the handler unauthenticated, so the page
// can render differently rather than forcing a login.
app.get('/', cas.gateway, ( req, res ) => {
  const user = req.session[cas.session_name];
  res.send(user ? `<html><body>Hello ${user}!</body></html>`
                : '<html><body>Hello stranger. <a href="/login">Sign in</a></body></html>');
});

// Unauthenticated clients will be redirected to the CAS login and then to the
// provided "returnTo" query parameter once authenticated.
app.get('/authenticate', cas.bounce_redirect);

// This route will de-authenticate the client with the Express server and then
// redirect the client to the CAS logout page.
app.get('/logout', cas.logout);

// This route will authenticate the client with the Express server and then
// redirect the client to the CAS login page.
app.get('/login', cas.login);
```

### Validation failures

A ticket that CAS rejects, a CAS server that cannot be reached, one that times
out, and one that reports success without a username are all treated the same
way: `bounce` and `block` answer 401, and `gateway` continues unauthenticated.

The username case matters more than it looks. An empty username would be stored
in the session as `''`, which is falsy, so the client would look unauthenticated
on the very next request and be sent back to CAS - indefinitely. It is refused
instead.

### The returnTo parameter

`bounce_redirect` and `login` both accept a `returnTo` query parameter naming
where to send the client once they are authenticated. Because that value comes
from the client, only a same-origin path is accepted: it has to begin with a
single `/`. An absolute URL, a protocol-relative `//host` path, or a scheme such
as `javascript:` is refused, and the client goes to the requested path instead.

Without that restriction an attacker could hand a victim a link that logs them
in at the real CAS server and then lands them on a site of the attacker's
choosing - a ready-made phishing flow. Versions before 0.3.0 redirected to
whatever `returnTo` contained.

### Mounting on a sub-path

The service URL sent to CAS is built from `req.originalUrl`, so mounting the
middleware inside a router works as you would expect:

```javascript
const router = require('express').Router();
router.get('/page', cas.bounce, ( req, res ) => res.send('Hello!'));
app.use('/portal', router);
// CAS is sent service=https://my-service-host.com/portal/page
```

Set `service_url` to the application's origin only - do not include the mount
prefix. Versions before 0.3.0 built the service URL from the mount-relative
path, which sent CAS a path with the prefix missing; if you compensated by
putting the prefix into `service_url`, remove it.

## Gateway mode

`bounce` and `block` both force a decision: log in, or be refused. Gateway mode
is the third option in the CAS protocol. It asks the CAS server "does this
client already have a single sign-on session?" and accepts "no" as an answer.

```javascript
app.get('/', cas.gateway, ( req, res ) => {
  if (req.session[cas.session_name]) {
    // Signed in elsewhere already - no login page was shown.
  } else {
    // No CAS session. The request still got here.
  }
});
```

This is what you want for a landing page that should greet a signed-in user by
name but stay open to anonymous visitors.

Three things worth knowing:

- **At most one gateway redirect is made per client.** Without that, a visitor
  with no CAS session would be bounced to the CAS server on every single
  request. The check is recorded in two places: under
  `req.session[CASAuthentication.GATEWAY_SESSION_FLAG]` (`'cas_gateway_attempted'`),
  and as a `cas_gateway=1` parameter on the service URL handed to CAS
  (`CASAuthentication.GATEWAY_QUERY_PARAM`). The second matters because it does
  not depend on the session surviving: a visitor with cookies blocked, or a
  crawler, would otherwise redirect between your app and CAS until the browser
  gave up. `logout` clears the session flag, and you can delete it yourself to
  force a fresh check.
- **A gateway check never blocks.** If CAS issues a ticket and validation then
  fails - a stale ticket from a page refresh, a service mismatch behind a proxy -
  the request continues unauthenticated rather than returning 401. `bounce` still
  returns 401 in that situation, because there the client did ask to log in.
- **`renew` takes precedence over gateway**, as the CAS protocol requires. With
  `renew: true` configured, `gateway` behaves like `bounce`: CAS is asked for a
  real login every time, and abandoning the login form does not turn the route
  anonymous.

### Gateway limitations

CAS gives a service no way to distinguish "the client came back from a gateway
check with no session" from "the client just navigated here", so the marker
above is the only available signal. Two consequences follow, and both are
deliberate:

- **A client with no usable session costs one CAS round trip per page view.**
  The marker only covers the return hop. This is bounded per request rather than
  per client, which is the price of not looping forever. If you serve a lot of
  cookie-less traffic (crawlers especially) on gateway routes, expect the extra
  requests at your CAS server, and consider `bounce` or no middleware on the
  paths crawlers actually fetch.
- **Anyone can put `?cas_gateway=1` in a link**, which suppresses the check for
  that one request, so a user who would have been signed in transparently sees
  the page anonymously. Honouring the marker only when no session exists would
  reintroduce the redirect loop, because a session that never persists is
  indistinguishable from one that does. The impact is one anonymous render: the
  pass-through deliberately records nothing, so the next request checks again.
  Do not use `gateway` where rendering anonymously is a security decision -
  use `block` or `bounce` for that.

## Passport strategy

A Passport strategy is available as a separate entry point. It wraps the same
ticket validation the middleware uses, so it supports CAS 1.0, 2.0, 3.0 and
SAML 1.1 identically.

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

Omit the verify callback and the CAS profile itself becomes `req.user`.

### Strategy options

In addition to every option in the table above:

| Name | Type | Description | Default |
|:-----|:----:|:------------|:-------:|
| cas | _CASAuthentication_ | An existing instance to reuse instead of constructing one from these options. | _(none)_ |
| name | _string_ | The name Passport registers the strategy under. | _"cas"_ |
| passReqToCallback | _boolean_ | Pass `req` as the verify callback's first argument. | _false_ |

Pass `{ gateway: true }` to `passport.authenticate` for a gateway check. The
strategy calls `pass()` when the client turns out to have no CAS session, and
also when a returned ticket fails validation, so the request continues down the
middleware chain either way. It works with or without session support.

```javascript
app.get('/', passport.authenticate('cas', { gateway: true }), ( req, res ) => {
  res.send(req.user ? `Hello ${req.user.user}!` : 'Hello stranger.');
});
```

`passport` itself is not a dependency of this package - install it yourself.

## TypeScript

Declarations ship with the package. They describe the middleware in terms of
Express's own `RequestHandler`, so a TypeScript project also needs
`@types/express` - declared as an optional peer dependency, and almost certainly
already present if you are writing an Express app in TypeScript:

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

The session keys this library writes are declared by augmenting
`express-session`, which is how you get typed access to them:

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

Note that for CAS 2.0 and 3.0 the attribute names released by CAS are
lower-cased, because they arrive as XML tags. A CAS `displayName` reaches the
session as `displayname`. SAML 1.1 preserves the case as sent.

Attribute *values* are typed as `CASAttributeValue`, which is deliberately wider
than `string`: a nested CAS attribute comes through as an object, and a SAML 1.1
value carrying no `xsi:type` comes through as `undefined`. Narrow before use.

```typescript
const raw = req.session.cas_userinfo?.memberOf;
const groups = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
```

## Tests

```
$ npm test
```

This runs the test suite on Node's built-in test runner and then type-checks the
declarations against a consumer-shaped usage file. No CAS server is needed - the
tests stand up a local HTTP server that plays the part of one.
