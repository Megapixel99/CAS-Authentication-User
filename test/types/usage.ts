/**
 * Consumer-shaped usage of the shipped declarations. This file is only ever
 * type-checked (npm run typecheck); it is never executed.
 */
import express = require('express');
import 'express-session';
import passport = require('passport');
import CASAuthentication = require('../../index');
import CasStrategy = require('../../strategy');

/**
 * The library writes a handful of fixed session keys, plus whichever key
 * `session_name`/`session_info` name. Declaring them is how a TypeScript
 * consumer gets typed access to them.
 */
declare module 'express-session' {
  interface SessionData {
    cas_user?: string;
    cas_userinfo?: CASAuthentication.CASAttributes;
    cas_return_to?: string;
    userType?: string;
    cas_gateway_attempted?: boolean;
  }
}

const app = express();

// --- Core middleware ---------------------------------------------------------

const cas = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
  cas_version: '3.0',
  renew: false,
  is_dev_mode: false,
  dev_mode_user: '',
  dev_mode_info: {},
  session_name: 'cas_user',
  session_info: 'cas_userinfo',
  destroy_session: false,
});

// A minimal configuration is enough.
const minimal = new CASAuthentication({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
});

app.get('/app', cas.bounce, (req, res) => { res.send('hello'); });
app.get('/api', cas.block, (req, res) => { res.json({ ok: true }); });
app.get('/maybe', cas.gateway, (req, res) => { res.json({ ok: true }); });
app.get('/authenticate', cas.bounce_redirect);
app.get('/login', cas.login);
app.get('/logout', cas.logout);

// Reading the session variables back out, once SessionData is augmented.
app.get('/api/user', cas.block, (req, res) => {
  const user: string | undefined = req.session.cas_user;
  const attributes: CASAuthentication.CASAttributes | undefined = req.session.cas_userinfo;
  res.json({ cas_user: user, cas_userinfo: attributes });
});

// A dynamic lookup by the configured session_name needs an explicit widening.
app.get('/api/whoami', cas.block, (req, res) => {
  const session = req.session as unknown as Record<string, unknown>;
  res.json({ cas_user: session[cas.session_name] });
});

// The gateway query marker is exported alongside the session flag.
const marker: string = CASAuthentication.GATEWAY_QUERY_PARAM;

// Forcing a fresh gateway check.
app.get('/recheck', (req, res, next) => {
  delete req.session.cas_gateway_attempted;
  next();
}, cas.gateway);

// Introspecting the instance.
const version: CASAuthentication.CasVersion = cas.cas_version;
const port: number = cas.cas_port;
const info: string | false = cas.session_info;

// Validating a ticket directly.
cas._validateTicket({ ticket: 'ST-1', service: 'https://my-service-host.com/app' },
  (err, user, attributes) => {
    if (err) { return; }
    const name: string | undefined = user;
    const email = attributes ? attributes.email : undefined;
    void name;
    void email;
  });

// --- Passport strategy -------------------------------------------------------

// Constructed from CAS options directly.
passport.use(new CasStrategy({
  cas_url: 'https://my-cas-host.com/cas',
  service_url: 'https://my-service-host.com',
  name: 'cas',
}));

// Reusing an existing client, with a verify callback.
passport.use(new CasStrategy({ cas }, (profile, done) => {
  const netid: string = profile.user;
  // Attribute values must be narrowed: CAS can release nested objects, and a
  // SAML value with no xsi:type comes through undefined.
  const raw = profile.attributes.memberOf;
  const groups: string[] = typeof raw === 'string' ? [raw]
    : (Array.isArray(raw) && raw.every((v) => typeof v === 'string') ? raw as string[] : []);
  done(null, { netid, groups });
}));

// passReqToCallback flips the verify signature.
passport.use(new CasStrategy({ cas, passReqToCallback: true }, (req, profile, done) => {
  void req.headers;
  done(null, { netid: profile.user });
}));

// The named export matches the CommonJS shape.
passport.use(new CasStrategy.Strategy({ cas }));

app.get('/passport', passport.authenticate('cas', { session: false }), (req, res) => {
  res.json({ user: req.user });
});

// A gateway check through Passport.
app.get('/passport-maybe', passport.authenticate('cas', { gateway: true } as passport.AuthenticateOptions), (req, res) => {
  res.json({ user: req.user });
});

const strategy = new CasStrategy({ cas });
const strategyName: string = strategy.name;
const client: CASAuthentication = strategy.cas;

// --- Things that must not type-check ----------------------------------------

// @ts-expect-error cas_url is required
new CASAuthentication({ service_url: 'https://my-service-host.com' });

// @ts-expect-error service_url is required
new CASAuthentication({ cas_url: 'https://my-cas-host.com/cas' });

// @ts-expect-error 4.0 is not a supported CAS version
new CASAuthentication({ cas_url: 'x', service_url: 'y', cas_version: '4.0' });

// @ts-expect-error a configuration object is required
new CASAuthentication();

// @ts-expect-error the verify callback must be a function
new CasStrategy({ cas }, 'nope');

declare const someAttributes: CASAuthentication.CASAttributes;

// @ts-expect-error an attribute value is not necessarily a string
const notAString: string = someAttributes.displayname;

// @ts-expect-error a nested attribute object has no string methods
someAttributes.address.toUpperCase();

void minimal; void version; void port; void info; void strategyName; void client; void app;
void marker; void notAString;
