import { RequestHandler } from 'express';

/**
 * A CAS authentication library designed to be used as middleware for an
 * Express server.
 */
declare class CASAuthentication {
  constructor(options: CASAuthentication.CASOptions);

  /** The CAS protocol version in use. */
  readonly cas_version: CASAuthentication.CasVersion;
  /** The configured CAS server URL. */
  readonly cas_url: string;
  /** Hostname parsed out of `cas_url`. */
  readonly cas_host: string;
  /**
   * Port used to reach the CAS server. An explicit port in `cas_url` is
   * honoured; without one the port follows the protocol (80 for http, 443 for
   * https).
   */
  readonly cas_port: number;
  /** Path parsed out of `cas_url`. */
  readonly cas_path: string;
  /** The configured service URL. */
  readonly service_url: string;
  readonly renew: boolean;
  readonly is_dev_mode: boolean;
  readonly dev_mode_user: string;
  readonly dev_mode_info: CASAuthentication.CASAttributes;
  /** Session key holding the authenticated username. */
  readonly session_name: string;
  /** Session key holding the CAS attributes, or `false` when not forwarded. */
  readonly session_info: string | false;
  readonly destroy_session: boolean;
  /** Milliseconds before a ticket validation request is abandoned. */
  readonly timeout: number;
  /** Whether the session id is regenerated on successful login. */
  readonly regenerate_session: boolean;

  /**
   * Redirects an unauthenticated client to the CAS login page and then back to
   * the requested page.
   */
  bounce: RequestHandler;

  /**
   * Like `bounce`, but once authenticated the client is redirected to the
   * `returnTo` query parameter.
   */
  bounce_redirect: RequestHandler;

  /** Denies access to an unauthenticated client with a 401 response. */
  block: RequestHandler;

  /**
   * Performs a CAS gateway check: authenticates the client transparently if a
   * single sign-on session already exists, and otherwise continues
   * unauthenticated rather than presenting a login form.
   *
   * At most one gateway redirect is made per client, recorded in the session
   * and on the returned URL. Delete
   * `req.session[CASAuthentication.GATEWAY_SESSION_FLAG]` to force a re-check.
   * A ticket rejected on this path continues unauthenticated rather than 401.
   */
  gateway: RequestHandler;

  /** Redirects the client to the CAS login page. */
  login: RequestHandler;

  /**
   * De-authenticates the client with the Express server and then redirects
   * them to the CAS logout page.
   */
  logout: RequestHandler;

  /**
   * Validates a service ticket against the CAS server, independently of any
   * request or session. Exposed for building alternative front ends; the
   * Passport strategy in `cas-authentication-user/strategy` wraps this.
   */
  _validateTicket(
    params: CASAuthentication.ValidateTicketParams,
    callback: (err: Error | null, user?: string, attributes?: CASAuthentication.CASAttributes) => void,
  ): void;
}

declare namespace CASAuthentication {
  /** Supported CAS protocol versions. */
  type CasVersion = '1.0' | '2.0' | '3.0' | 'saml1.1';

  /**
   * A single attribute value. Nested attribute elements are passed through as
   * xml2js built them, so a value can be an object as well as a string, and a
   * SAML 1.1 value with no XML attributes comes through as `undefined`. Narrow
   * before use.
   */
  type CASAttributeValue =
    | string
    | string[]
    | CASAttributes
    | CASAttributes[]
    | undefined;

  /**
   * Attributes released by the CAS server.
   *
   * Note that for CAS 2.0 and 3.0 the attribute names are lower-cased, so a
   * CAS `displayName` arrives as `displayname`. SAML 1.1 attribute names are
   * preserved as sent.
   */
  interface CASAttributes {
    [key: string]: CASAttributeValue;
  }

  interface CASOptions {
    /** The URL of the CAS server. */
    cas_url: string;
    /**
     * The URL of the application, registered with the CAS server as a valid
     * service.
     */
    service_url: string;
    /** The CAS protocol version. Defaults to `'3.0'`. */
    cas_version?: CasVersion;
    /**
     * Require login regardless of whether a single sign-on session already
     * exists. Takes precedence over a gateway check. Defaults to `false`.
     */
    renew?: boolean;
    /**
     * Skip CAS entirely and authenticate as `dev_mode_user`. Defaults to
     * `false`.
     */
    is_dev_mode?: boolean;
    /** The CAS user to use when dev mode is active. Defaults to `''`. */
    dev_mode_user?: string;
    /** The CAS attributes to use when dev mode is active. Defaults to `{}`. */
    dev_mode_info?: CASAttributes;
    /**
     * Name of the session variable holding the authenticated CAS user.
     * Defaults to `'cas_user'`.
     */
    session_name?: string;
    /**
     * Name of the session variable holding the CAS attributes, or a falsy
     * value to not forward them. Ignored for CAS 1.0, which cannot supply
     * attributes. Defaults to `false`.
     */
    session_info?: string | false;
    /**
     * Destroy the entire session on logout rather than only the CAS session
     * variables. Defaults to `false`.
     */
    destroy_session?: boolean;
    /**
     * Milliseconds to wait for the CAS server to answer a ticket validation
     * request before giving up. `0` waits indefinitely. Defaults to `10000`.
     */
    timeout?: number;
    /**
     * Regenerate the session id on successful login, so a session fixed by an
     * attacker beforehand does not carry over. Application data in the session
     * is preserved; only the id changes. Defaults to `true`.
     */
    regenerate_session?: boolean;
  }

  interface ValidateTicketParams {
    /** The service ticket issued by CAS. */
    ticket: string;
    /** The service URL the ticket was issued for. */
    service: string;
    /** Host used to build the SAML 1.1 RequestID. */
    host?: string;
  }

  /**
   * Session key recording that a gateway check has already been made. Delete it
   * from the session to force a fresh check.
   */
  const GATEWAY_SESSION_FLAG: string;

  /**
   * Query parameter added to the service URL of a gateway redirect, so that the
   * check terminates even for a client whose session does not persist.
   */
  const GATEWAY_QUERY_PARAM: string;

  /**
   * Serialises query parameters the way the CAS service URL requires: a space
   * as `%20` and `~!*()` left literal, matching what this library has always
   * sent. Shared with the Passport strategy, which builds the same login URL.
   */
  function formatQuery(params: Record<string, string | number | boolean>): string;
}

export = CASAuthentication;
