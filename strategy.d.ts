import { Request } from 'express';
import CASAuthentication = require('./index');

/**
 * A Passport strategy for CAS.
 *
 * A thin wrapper over `CASAuthentication`: ticket validation, protocol
 * selection and XML parsing are all delegated to the core, so the strategy
 * supports CAS 1.0, 2.0, 3.0 and SAML 1.1.
 */
declare class CasStrategy {
  /** With `passReqToCallback: true`, the verify callback receives `req` first. */
  constructor(
    options: CasStrategy.StrategyOptionsWithRequest,
    verify: CasStrategy.VerifyCallbackWithRequest,
  );
  constructor(
    options: CasStrategy.StrategyOptions,
    verify?: CasStrategy.VerifyCallback,
  );

  /** The name Passport registers the strategy under. Defaults to `'cas'`. */
  name: string;

  /** The underlying CAS client, either supplied or constructed from options. */
  cas: CASAuthentication;

  /** Called by Passport. Not usually invoked directly. */
  authenticate(req: Request, options?: CasStrategy.AuthenticateOptions): void;
}

declare namespace CasStrategy {
  /** The CAS identity handed to the verify callback. */
  interface CASProfile {
    provider: 'cas';
    /** The CAS username. */
    id: string;
    /** The CAS username. */
    user: string;
    /** Attributes released by CAS, `{}` if none. */
    attributes: CASAuthentication.CASAttributes;
  }

  type DoneCallback = (err: any, user?: any, info?: any) => void;

  type VerifyCallback = (profile: CASProfile, done: DoneCallback) => void;

  type VerifyCallbackWithRequest = (
    req: Request,
    profile: CASProfile,
    done: DoneCallback,
  ) => void;

  interface StrategyExtraOptions {
    /** An existing `CASAuthentication` instance to reuse. */
    cas?: CASAuthentication;
    /** The name Passport registers the strategy under. Defaults to `'cas'`. */
    name?: string;
    /** Pass `req` as the verify callback's first argument. Defaults to `false`. */
    passReqToCallback?: boolean;
  }

  /**
   * Either the full set of CAS options, or `{cas}` wrapping an existing
   * instance. Both forms accept the extra strategy-only options.
   */
  type StrategyOptions =
    | (CASAuthentication.CASOptions & StrategyExtraOptions)
    | (StrategyExtraOptions & { cas: CASAuthentication });

  /** Options requiring the request-first verify signature. */
  type StrategyOptionsWithRequest = StrategyOptions & { passReqToCallback: true };

  interface AuthenticateOptions {
    /**
     * Make a silent gateway check instead of redirecting to a login form.
     * Results in `pass()` when the client has no single sign-on session, and
     * also when a returned ticket fails validation - a gateway check never
     * blocks. Works with or without session support.
     */
    gateway?: boolean;
  }

  /** Also available as a named export, matching the CommonJS shape. */
  const Strategy: typeof CasStrategy;
}

export = CasStrategy;
