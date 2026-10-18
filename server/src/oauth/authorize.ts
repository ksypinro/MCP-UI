/**
 * The authorization endpoint and the pages behind it.
 *
 * Shape of the flow:
 *
 *   GET  /authorize   validates everything once, stores the result server-side
 *                     under an opaque id bound to this browser, and sends the
 *                     person to sign in or straight to approval.
 *   POST /par         the same validation for parameters pushed over the back
 *                     channel (RFC 9126); GET /authorize then takes only
 *                     client_id and the request_uri. Required for our own app.
 *   GET  /login       sign in or sign up. POST starts an authorization-server
 *                     session and moves on to approval.
 *   GET  /consent     names the client, where it will send them, and what it
 *                     asks for. Skipped when an equivalent approval is
 *                     remembered (see consents.ts). POST issues the code.
 *   POST /consent/deny, /authorize/cancel   access_denied back to the client.
 *   POST /logout      ends the session and returns to sign-in.
 *
 * Every step after the first requires the browser-binding cookie set at
 * GET /authorize and a CSRF token derived from it, so a pending id copied to
 * another browser, or a form posted from another site, gets nowhere.
 */

import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { isAppError } from '../errors.ts';
import { createAccount, getAccount, verifyCredentials } from '../domain/accounts.ts';
import {
  API_RESOURCE, ISSUER, PAR_TTL_SECONDS, RESOURCE_URI, SCOPES, parseScopes, requestsOfflineAccess
} from './config.ts';
import { currentDpopNonce } from './dpop.ts';
import { redirectUriAllowed, resolveClient } from './clients.ts';
import {
  claimAndIssueCode, createPendingAuthorization, deletePendingAuthorization, pendingBelongsTo,
  readPendingAuthorization, storePushedRequest, takePushedRequest,
  type NewPendingAuthorization, type PendingAuthorization
} from './store.ts';
import { findRememberedConsent, recordConsent } from './consents.ts';
import {
  AS_SESSION_ABSOLUTE_SECONDS, readAsSession, revokeAsSession, startAsSession, type AsSession
} from './session.ts';
import { renderConsentPage, renderErrorPage, renderLoginPage } from './pages.ts';
import { authPageHeaders, formActionSource, newNonce } from '../security/headers.ts';
import { clearCookie, cookieName, readCookie, setCookie } from '../security/cookies.ts';
import { mac, macMatches } from '../security/mac.ts';
import { mint, wellFormed } from '../tokens/format.ts';

/** Approving write access needs a sign-in at most this old. */
const RECENT_SIGN_IN_SECONDS = 15 * 60;
/** How long the browser-binding cookie lives: longer than any pending flow. */
const BINDING_COOKIE_SECONDS = 60 * 60;

/**
 * Sends one of our own pages. Every HTML response goes through here so that
 * none can be framed or skip the CSP; see security/headers.ts.
 */
function sendPage(
  res: Response, status: number, render: (nonce: string) => string, formTargets: string[] = []
): void {
  const nonce = newNonce();
  authPageHeaders(res, { nonce, formTargets });
  res.status(status).type('html').send(render(nonce));
}

function sendError(res: Response, title: string, detail: string, status = 400): void {
  sendPage(res, status, (nonce) => renderErrorPage(title, detail, nonce));
}

/**
 * Sends an error back to the client's registered redirect URI.
 *
 * Only ever called with a redirect_uri that has already been validated against
 * the resolved client. An unvalidated one is reported on our own page
 * instead — redirecting to it would make this endpoint an open redirector.
 */
function redirectWithError(
  res: Response, redirectUri: string, state: string | null, error: string, description: string
): void {
  const location = new URL(redirectUri);
  location.searchParams.set('error', error);
  location.searchParams.set('error_description', description);
  if (state) location.searchParams.set('state', state);
  location.searchParams.set('iss', ISSUER); // RFC 9207 applies to error responses too
  res.redirect(302, location.toString());
}

/** This browser's binding value, minting and setting one if it has none. */
function ensureBinding(req: Request, res: Response): string {
  const existing = readCookie(req, cookieName('pa'));
  if (wellFormed('binding', existing)) return existing;
  const fresh = mint('binding');
  setCookie(res, cookieName('pa'), fresh, BINDING_COOKIE_SECONDS);
  return fresh;
}

/** The CSRF token for every form of one pending authorization in one browser. */
function csrfFor(pending: PendingAuthorization, binding: string): string {
  return mac('authorize-csrf', pending.id, binding);
}

function stepUrl(
  step: 'login' | 'consent', pending: PendingAuthorization, extra: Record<string, string> = {}
): string {
  return `/${step}?${new URLSearchParams({ pending: pending.id, ...extra }).toString()}`;
}

function writes(pending: PendingAuthorization): boolean {
  return pending.scopes.some((scope) => scope !== 'devices:read');
}

/** Whether this session may approve this request without signing in again. */
function recentEnough(pending: PendingAuthorization, session: AsSession): boolean {
  return !writes(pending) || session.authAgeSeconds <= RECENT_SIGN_IN_SECONDS;
}

const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';

function parRequestId(requestUri: string): string {
  return requestUri.startsWith(REQUEST_URI_PREFIX) ? requestUri.slice(REQUEST_URI_PREFIX.length) : '';
}

type Validated =
  | { ok: true; pending: NewPendingAuthorization; startWithSignUp: boolean }
  | {
      ok: false; title: string; detail: string;
      /** Set once the redirect URI is known to be the client's; errors then go there. */
      redirect?: { redirectUri: string; state: string | null; error: string; description: string };
    };

/**
 * Checks an authorization request once, wherever it came from: the query of
 * GET /authorize, or the body of a pushed request. The order matters: until
 * the client and its redirect URI are established, errors stay on our own
 * page, so this endpoint is never an open redirector.
 */
async function validateAuthorization(
  db: Db, params: Record<string, unknown>, origin: { pushed: boolean }
): Promise<Validated> {
  const {
    client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method,
    resource, scope, dpop_jkt, prompt
  } = params;

  const client = await resolveClient(db, client_id);
  if (!client) {
    return {
      ok: false, title: 'Unrecognised application',
      detail: 'The application that sent you here could not be identified. Its client_id is not registered and does not resolve to a client metadata document.'
    };
  }
  if (typeof redirect_uri !== 'string' || !redirectUriAllowed(redirect_uri, client.redirectUris)) {
    return {
      ok: false, title: 'Unrecognised redirect address',
      detail: 'The application asked to be sent somewhere it has not registered, so nothing was sent.'
    };
  }

  // Bounded: state is echoed back verbatim and stored until the
  // authorization completes, so an unbounded one is free storage.
  const stateValue = typeof state === 'string' && state.length <= 2048 ? state : null;
  const refuse = (error: string, description: string): Validated => ({
    ok: false, title: 'This request could not be accepted', detail: description,
    redirect: { redirectUri: redirect_uri, state: stateValue, error, description }
  });

  // Our own app pushes its parameters, so they never travel through the
  // browser where they could be read or altered.
  if (client.firstParty && !origin.pushed) {
    return refuse('invalid_request', 'This application must use pushed authorization requests.');
  }
  if (response_type !== 'code') {
    return refuse('unsupported_response_type', 'Only the authorization code flow is supported.');
  }
  if (code_challenge_method !== 'S256' || typeof code_challenge !== 'string'
      || code_challenge.length < 43 || code_challenge.length > 128) {
    return refuse('invalid_request', 'PKCE with the S256 challenge method is required.');
  }

  // RFC 8707: a token is minted for one resource. Third-party clients get
  // the MCP endpoint and nothing else; our own app gets the REST API and
  // nothing else. Quietly issuing a token for a resource other than the one
  // asked for would be exactly the confused-deputy problem the parameter
  // exists to prevent.
  const expectedResource = client.firstParty ? API_RESOURCE : RESOURCE_URI;
  if (resource !== undefined && resource !== expectedResource) {
    return refuse('invalid_target', `This client may only request tokens for ${expectedResource}.`);
  }

  const requested = scope === undefined ? [...SCOPES] : parseScopes(scope);
  if (requested.length === 0) {
    // Issuing a token that authorizes nothing would leave the client in a
    // step-up loop it can never satisfy.
    return refuse('invalid_scope', `Supported scopes are: ${SCOPES.join(' ')}`);
  }

  // RFC 9449 section 10: committing to a DPoP key at authorization time
  // binds the code to it. Our own app always does.
  if (dpop_jkt !== undefined && (typeof dpop_jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(dpop_jkt))) {
    return refuse('invalid_request', 'dpop_jkt must be a base64url SHA-256 JWK thumbprint.');
  }
  if (client.firstParty && dpop_jkt === undefined) {
    return refuse('invalid_request', 'This client must bind its authorization to a DPoP key.');
  }

  return {
    ok: true,
    startWithSignUp: prompt === 'create',
    pending: {
      clientId: client.clientId,
      clientHost: client.displayHost ?? (new URL(redirect_uri).host || new URL(redirect_uri).protocol),
      clientKind: client.kind,
      clientTrust: client.trust,
      documentDigest: client.documentDigest,
      redirectUri: redirect_uri,
      state: stateValue,
      codeChallenge: code_challenge,
      resource: expectedResource,
      scopes: requested,
      offlineAccess: scope === undefined || requestsOfflineAccess(scope),
      dpopJkt: typeof dpop_jkt === 'string' ? dpop_jkt : null,
      firstParty: client.firstParty
    }
  };
}

export function authorizeRoutes(db: Db): Router {
  const router = Router();

  /**
   * The pending authorization named by `id`, if it exists and was started in
   * this browser. Renders the error page itself and returns null otherwise.
   */
  async function loadStep(
    req: Request, res: Response, id: unknown
  ): Promise<{ pending: PendingAuthorization; binding: string } | null> {
    const pending = await readPendingAuthorization(db, id);
    if (!pending) {
      sendError(res, 'This sign-in link has expired', 'Authorizations are only valid for a few minutes.');
      return null;
    }
    const binding = readCookie(req, cookieName('pa'));
    if (!pendingBelongsTo(pending, binding)) {
      sendError(res,
        'Open this in the browser you started from',
        'This sign-in was started in a different browser, or its cookie was cleared.');
      return null;
    }
    return { pending, binding: binding as string };
  }

  async function currentSession(req: Request): Promise<AsSession | null> {
    return readAsSession(db, readCookie(req, cookieName('as_session')));
  }

  /** Claims the pending authorization and sends the code to the client. */
  async function complete(
    res: Response, pending: PendingAuthorization, session: AsSession, consentId: string | null
  ): Promise<void> {
    const code = await claimAndIssueCode(db, session.accountId, pending, {
      authTime: session.authTime, consentId
    });
    if (!code) {
      sendError(res,
        'This sign-in link has already been used',
        'Start again from the app that sent you here.');
      return;
    }
    const location = new URL(pending.redirectUri);
    location.searchParams.set('code', code);
    if (pending.state) location.searchParams.set('state', pending.state);
    location.searchParams.set('iss', ISSUER);
    res.redirect(302, location.toString());
  }

  function renderLogin(
    res: Response, pending: PendingAuthorization, binding: string,
    options: { mode: 'login' | 'signup'; reauth?: boolean; error?: string; username?: string }
  ): void {
    // The cancel form's submission ends in a redirect to the client, so the
    // CSP has to allow that destination as a form target.
    sendPage(res, 200, (nonce) => renderLoginPage({
      nonce,
      pendingId: pending.id,
      csrf: csrfFor(pending, binding),
      clientHost: pending.clientHost,
      ...options
    }), [formActionSource(pending.redirectUri)]);
  }

  function refuseForm(res: Response): void {
    sendError(res, 'This form has expired', 'Reload the page and try again.', 403);
  }

  /* -------------------------------------------------------- /authorize */

  router.get('/authorize', async (req: Request, res: Response) => {
    // A resume link from an older page.
    if (typeof req.query.pending === 'string') {
      res.redirect(303, `/login?${new URLSearchParams({ pending: req.query.pending }).toString()}`);
      return;
    }

    // RFC 9126: with a request_uri, the parameters were pushed over the back
    // channel and are taken from there; anything else in the query except
    // client_id is ignored, so nothing the browser carries can change them.
    let validated: Validated;
    if (typeof req.query.request_uri === 'string') {
      const pushed = typeof req.query.client_id === 'string'
        ? await takePushedRequest(db, parRequestId(req.query.request_uri), req.query.client_id)
        : null;
      if (!pushed) {
        sendError(res, 'This sign-in link has expired', 'Start again from the app that sent you here.');
        return;
      }
      validated = await validateAuthorization(db, pushed, { pushed: true });
    } else {
      validated = await validateAuthorization(db, req.query, { pushed: false });
    }

    if (!validated.ok) {
      if (validated.redirect) {
        const { redirectUri, state, error, description } = validated.redirect;
        redirectWithError(res, redirectUri, state, error, description);
      } else {
        sendError(res, validated.title, validated.detail);
      }
      return;
    }

    const binding = ensureBinding(req, res);
    const pendingId = await createPendingAuthorization(db, validated.pending, binding);
    const signedIn = Boolean(await currentSession(req));
    const query = new URLSearchParams({ pending: pendingId });
    if (!signedIn && validated.startWithSignUp) query.set('mode', 'signup');
    res.redirect(303, `/${signedIn ? 'consent' : 'login'}?${query.toString()}`);
  });

  /* -------------------------------------------------------------- /par */

  /**
   * Pushed authorization requests (RFC 9126). Validated exactly as
   * /authorize would, but errors come back as JSON to the client rather than
   * to the browser, and nothing is redirected.
   */
  router.post('/par', async (req: Request, res: Response) => {
    res.set('Cache-Control', 'no-store').set('DPoP-Nonce', currentDpopNonce());
    const body = (req.body ?? {}) as Record<string, unknown>;
    const validated = await validateAuthorization(db, body, { pushed: true });
    if (!validated.ok) {
      const error = validated.redirect?.error ?? (validated.title === 'Unrecognised application' ? 'invalid_client' : 'invalid_request');
      res.status(400).json({ error, error_description: validated.redirect?.description ?? validated.detail });
      return;
    }
    const params: Record<string, string> = {};
    for (const [key, value] of Object.entries(body)) if (typeof value === 'string') params[key] = value;
    const id = await storePushedRequest(db, validated.pending.clientId, params);
    res.status(201).json({ request_uri: `${REQUEST_URI_PREFIX}${id}`, expires_in: PAR_TTL_SECONDS });
  });

  /* ------------------------------------------------------------ /login */

  router.get('/login', async (req: Request, res: Response) => {
    const step = await loadStep(req, res, req.query.pending);
    if (!step) return;
    renderLogin(res, step.pending, step.binding, {
      mode: req.query.mode === 'signup' ? 'signup' : 'login',
      reauth: req.query.reauth === '1'
    });
  });

  router.post('/login', async (req: Request, res: Response) => {
    const step = await loadStep(req, res, req.body?.pending);
    if (!step) return;
    const { pending, binding } = step;
    if (!macMatches(csrfFor(pending, binding), req.body?.csrf)) return refuseForm(res);

    const mode = req.body?.mode === 'signup' ? 'signup' : 'login';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    let accountId: string;
    if (mode === 'signup') {
      try {
        accountId = (await createAccount(db, username, password)).id;
      } catch (error) {
        const message = isAppError(error) ? error.message : 'Could not create that account.';
        renderLogin(res, pending, binding, { mode: 'signup', error: message, username });
        return;
      }
    } else {
      const account = await verifyCredentials(db, username, password);
      if (!account) {
        // One generic failure for both an unknown username and a wrong
        // password, or this page becomes an account enumerator.
        renderLogin(res, pending, binding, { mode: 'login', error: 'Invalid username or password.', username });
        return;
      }
      accountId = account.id;
    }

    // Always a fresh session on sign-in, never an upgraded old one, so a
    // session id planted before sign-in cannot become an authenticated one.
    await revokeAsSession(db, readCookie(req, cookieName('as_session')));
    const token = await startAsSession(db, accountId, 'pwd');
    setCookie(res, cookieName('as_session'), token, AS_SESSION_ABSOLUTE_SECONDS);
    res.redirect(303, stepUrl('consent', pending));
  });

  /* ---------------------------------------------------------- /consent */

  router.get('/consent', async (req: Request, res: Response) => {
    const step = await loadStep(req, res, req.query.pending);
    if (!step) return;
    const { pending, binding } = step;

    const session = await currentSession(req);
    const account = session ? await getAccount(db, session.accountId) : null;
    if (!session || !account) {
      res.redirect(303, stepUrl('login', pending));
      return;
    }
    if (!recentEnough(pending, session)) {
      res.redirect(303, stepUrl('login', pending, { reauth: '1' }));
      return;
    }

    // Our own app: signing in is the whole of the consent.
    if (pending.firstParty) {
      await complete(res, pending, session, null);
      return;
    }

    const remembered = await findRememberedConsent(db, session.accountId, pending);
    if (remembered) {
      await complete(res, pending, session, remembered);
      return;
    }

    sendPage(res, 200, (nonce) => renderConsentPage({
      nonce,
      pendingId: pending.id,
      csrf: csrfFor(pending, binding),
      username: account.username,
      clientHost: pending.clientHost,
      clientKind: pending.clientKind,
      clientTrust: pending.clientTrust,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes
    }), [formActionSource(pending.redirectUri)]);
  });

  router.post('/consent', async (req: Request, res: Response) => {
    const step = await loadStep(req, res, req.body?.pending);
    if (!step) return;
    const { pending, binding } = step;
    if (!macMatches(csrfFor(pending, binding), req.body?.csrf)) return refuseForm(res);

    const session = await currentSession(req);
    if (!session) {
      res.redirect(303, stepUrl('login', pending));
      return;
    }
    if (!recentEnough(pending, session)) {
      res.redirect(303, stepUrl('login', pending, { reauth: '1' }));
      return;
    }

    const consentId = await recordConsent(db, session.accountId, pending);
    await complete(res, pending, session, consentId);
  });

  /* ------------------------------------------------------- deny, logout */

  async function deny(req: Request, res: Response): Promise<void> {
    const step = await loadStep(req, res, req.body?.pending);
    if (!step) return;
    const { pending, binding } = step;
    if (!macMatches(csrfFor(pending, binding), req.body?.csrf)) return refuseForm(res);
    await deletePendingAuthorization(db, pending.id);
    // Section 10.3 step 8: declining leaves the integration signed out and
    // performs no mutation. The client is told, rather than left hanging.
    redirectWithError(res, pending.redirectUri, pending.state, 'access_denied',
      'The person declined to authorize this application.');
  }

  router.post('/consent/deny', deny);
  router.post('/authorize/cancel', deny);

  router.post('/logout', async (req: Request, res: Response) => {
    const step = await loadStep(req, res, req.body?.pending);
    if (!step) return;
    if (!macMatches(csrfFor(step.pending, step.binding), req.body?.csrf)) return refuseForm(res);
    await revokeAsSession(db, readCookie(req, cookieName('as_session')));
    clearCookie(res, cookieName('as_session'));
    res.redirect(303, stepUrl('login', step.pending));
  });

  return router;
}
