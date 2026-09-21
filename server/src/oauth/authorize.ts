/**
 * The authorization endpoint and the hosted login it renders.
 *
 * Shape of the flow: GET validates everything once and stores the result
 * server-side under an opaque id; the browser carries only that id; POST reads
 * it back, authenticates the person, and redirects with a code.
 */

import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { AppError, isAppError } from '../errors.ts';
import { createAccount, verifyCredentials } from '../domain/accounts.ts';
import { ISSUER, RESOURCE_URI, SCOPES, parseScopes } from './config.ts';
import { redirectUriAllowed, resolveClient } from './clients.ts';
import {
  claimPendingAuthorization, createPendingAuthorization, deletePendingAuthorization,
  issueAuthorizationCode, readPendingAuthorization, type PendingAuthorization
} from './store.ts';
import { renderAuthorizePage, renderErrorPage } from './pages.ts';

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

function renderPending(res: Response, pending: PendingAuthorization, mode: 'login' | 'signup', error?: string, username?: string): void {
  res.type('html').send(renderAuthorizePage({
    pendingId: pending.id,
    clientHost: pending.clientHost,
    scopes: pending.scopes,
    mode,
    ...(error ? { error } : {}),
    ...(username ? { username } : {})
  }));
}

export function authorizeRoutes(db: Db): Router {
  const router = Router();

  router.get('/authorize', async (req: Request, res: Response) => {
    // Resuming an authorization already in flight — the mode tabs link here.
    if (req.query.pending !== undefined) {
      const pending = await readPendingAuthorization(db, req.query.pending);
      if (!pending) {
        res.status(400).type('html').send(renderErrorPage(
          'This sign-in link has expired',
          'Authorizations are only valid for a few minutes.'
        ));
        return;
      }
      renderPending(res, pending, req.query.mode === 'signup' ? 'signup' : 'login');
      return;
    }

    const {
      client_id, redirect_uri, response_type, state,
      code_challenge, code_challenge_method, resource, scope
    } = req.query;

    // Before anything can be sent to a redirect URI, that URI has to be one
    // this client is allowed to use. Until then errors stay on our own page.
    const client = await resolveClient(db, client_id);
    if (!client) {
      res.status(400).type('html').send(renderErrorPage(
        'Unrecognised application',
        'The application that sent you here could not be identified. Its client_id is not registered and does not resolve to a client metadata document.'
      ));
      return;
    }
    if (typeof redirect_uri !== 'string' || !redirectUriAllowed(redirect_uri, client.redirectUris)) {
      res.status(400).type('html').send(renderErrorPage(
        'Unrecognised redirect address',
        'The application asked to be sent somewhere it has not registered, so nothing was sent.'
      ));
      return;
    }

    // Bounded: state is echoed back verbatim and stored until the
    // authorization completes, so an unbounded one is free storage.
    const stateValue = typeof state === 'string' && state.length <= 2048 ? state : null;

    if (response_type !== 'code') {
      redirectWithError(res, redirect_uri, stateValue, 'unsupported_response_type',
        'Only the authorization code flow is supported.');
      return;
    }
    if (code_challenge_method !== 'S256' || typeof code_challenge !== 'string' || code_challenge.length < 43) {
      redirectWithError(res, redirect_uri, stateValue, 'invalid_request',
        'PKCE with the S256 challenge method is required.');
      return;
    }
    // RFC 8707: a token is minted for one resource. If a client asks for a
    // different one we cannot serve it, and quietly issuing a token for ours
    // instead would be exactly the confused-deputy problem the parameter
    // exists to prevent.
    if (resource !== undefined && resource !== RESOURCE_URI) {
      redirectWithError(res, redirect_uri, stateValue, 'invalid_target',
        `This authorization server only issues tokens for ${RESOURCE_URI}.`);
      return;
    }

    const requested = scope === undefined ? [...SCOPES] : parseScopes(scope);
    if (requested.length === 0) {
      // Issuing a token that authorizes nothing would leave the client in a
      // step-up loop it can never satisfy.
      redirectWithError(res, redirect_uri, stateValue, 'invalid_scope',
        `Supported scopes are: ${SCOPES.join(' ')}`);
      return;
    }

    const pendingId = await createPendingAuthorization(db, {
      clientId: client.clientId,
      clientHost: client.displayHost,
      redirectUri: redirect_uri,
      state: stateValue,
      codeChallenge: code_challenge,
      resource: RESOURCE_URI,
      scopes: requested
    });

    const pending = await readPendingAuthorization(db, pendingId);
    if (!pending) {
      redirectWithError(res, redirect_uri, stateValue, 'server_error', 'Could not start authorization.');
      return;
    }
    renderPending(res, pending, 'login');
  });

  router.post('/authorize', async (req: Request, res: Response) => {
    const pending = await readPendingAuthorization(db, req.body?.pending);
    if (!pending) {
      res.status(400).type('html').send(renderErrorPage(
        'This sign-in link has expired',
        'Authorizations are only valid for a few minutes.'
      ));
      return;
    }

    const mode = req.body?.mode === 'signup' ? 'signup' : 'login';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    let accountId: string;
    if (mode === 'signup') {
      try {
        accountId = (await createAccount(db, username, password)).id;
      } catch (error) {
        const message = isAppError(error) ? error.message : 'Could not create that account.';
        renderPending(res, pending, 'signup', message, username);
        return;
      }
    } else {
      const account = await verifyCredentials(db, username, password);
      if (!account) {
        // One generic failure for both an unknown username and a wrong
        // password, or this page becomes an account enumerator.
        renderPending(res, pending, 'login', new AppError('UNAUTHENTICATED').message, username);
        return;
      }
      accountId = account.id;
    }

    // Claim before issuing. Issuing first and deleting afterwards leaves a
    // window where two submissions mint two codes for one authorization.
    if (!(await claimPendingAuthorization(db, pending.id))) {
      res.status(400).type('html').send(renderErrorPage(
        'This sign-in link has already been used',
        'Start again from the app that sent you here.'
      ));
      return;
    }
    const code = await issueAuthorizationCode(db, accountId, pending);

    const location = new URL(pending.redirectUri);
    location.searchParams.set('code', code);
    if (pending.state) location.searchParams.set('state', pending.state);
    location.searchParams.set('iss', ISSUER);
    res.redirect(302, location.toString());
  });

  router.post('/authorize/cancel', async (req: Request, res: Response) => {
    const pending = await readPendingAuthorization(db, req.body?.pending);
    if (!pending) {
      res.status(400).type('html').send(renderErrorPage('Nothing to cancel', 'This authorization has already ended.'));
      return;
    }
    await deletePendingAuthorization(db, pending.id);
    // Section 10.3 step 8: cancelling leaves the integration signed out and
    // performs no mutation. The client is told, rather than left hanging.
    redirectWithError(res, pending.redirectUri, pending.state, 'access_denied',
      'The person declined to authorize this application.');
  });

  return router;
}
