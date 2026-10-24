/**
 * The account pages on the authorization server: passkeys (plan 4.5) and
 * connected apps (plan 4.6).
 *
 * They use the authorization server's own browser session and nothing else.
 * No token issued to any application is accepted here, so an application can
 * never manage the account it was given access to. Every form carries a CSRF
 * value bound to that session.
 *
 * Adding a passkey or changing the password gives access, so it needs a
 * sign-in in the last fifteen minutes. Removing a passkey, disconnecting an
 * app or signing out everywhere only takes access away, and does not.
 */

import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { isAppError } from '../errors.ts';
import { getAccount, verifyCredentials } from '../domain/accounts.ts';
import { mac, macMatches } from '../security/mac.ts';
import { clearCookie, cookieName, readCookie, setCookie } from '../security/cookies.ts';
import { wellFormed } from '../tokens/format.ts';
import {
  AS_SESSION_ABSOLUTE_SECONDS, readAsSession, revokeAsSession, startAsSession, type AsSession
} from './session.ts';
import { accountLoginCsrf, ensureBinding, sendPage } from './authorize.ts';
import { renderAccountLoginPage, renderAccountPage, renderAppsPage } from './pages.ts';
import { deletePasskey, finishRegistration, listPasskeys, registrationOptions } from './passkeys.ts';
import { changePassword, listConnectedApps, revokeConnectedApp, signOutEverywhere } from './account.ts';

const RECENT_SIGN_IN_SECONDS = 15 * 60;

const NOTICES: Record<string, string> = {
  'passkey-added': 'Passkey added.',
  'passkey-removed': 'Passkey removed.',
  'password-changed': 'Password changed. Everything else has been signed out.',
  'app-disconnected': 'Disconnected. That app can no longer reach your devices.',
  'signed-out': 'Signed out everywhere.'
};

function noticeFrom(req: Request): string | undefined {
  return typeof req.query.done === 'string' ? NOTICES[req.query.done] : undefined;
}

export function accountRoutes(db: Db): Router {
  const router = Router();

  interface Signed { session: AsSession; token: string; username: string; csrf: string }

  /** The signed-in account behind this request, or null. */
  async function signedIn(req: Request): Promise<Signed | null> {
    const token = readCookie(req, cookieName('as_session'));
    if (!wellFormed('session', token)) return null;
    const session = await readAsSession(db, token);
    const account = session ? await getAccount(db, session.accountId) : null;
    if (!session || !account) return null;
    return { session, token, username: account.username, csrf: mac('account-csrf', token) };
  }

  /** The signed-in account, if this form's CSRF value is its own. Otherwise sends the refusal. */
  async function forForm(req: Request, res: Response): Promise<Signed | null> {
    const who = await signedIn(req);
    if (!who) {
      res.redirect(303, '/account/login');
      return null;
    }
    if (!macMatches(who.csrf, req.body?.csrf)) {
      res.redirect(303, '/account');
      return null;
    }
    return who;
  }

  const recent = (who: Signed) => who.session.authAgeSeconds <= RECENT_SIGN_IN_SECONDS;

  function renderLogin(req: Request, res: Response, options: { error?: string; username?: string; status?: number } = {}): void {
    const binding = ensureBinding(req, res);
    sendPage(res, options.status ?? 200, (nonce) => renderAccountLoginPage({
      nonce, csrf: accountLoginCsrf(binding), error: options.error, username: options.username,
      notice: noticeFrom(req), reauth: req.query.reauth === '1'
    }), [], { script: true });
  }

  /* ------------------------------------------------------------- sign in */

  router.get('/account/login', (req, res) => renderLogin(req, res));

  router.post('/account/login', async (req: Request, res: Response) => {
    const binding = readCookie(req, cookieName('pa'));
    if (!wellFormed('binding', binding) || !macMatches(accountLoginCsrf(binding), req.body?.csrf)) {
      renderLogin(req, res, { error: 'This form expired. Try again.', status: 403 });
      return;
    }
    const account = await verifyCredentials(db, req.body?.username, req.body?.password);
    if (!account) {
      const username = typeof req.body?.username === 'string' ? req.body.username : '';
      renderLogin(req, res, { error: 'Invalid username or password.', username });
      return;
    }
    await revokeAsSession(db, readCookie(req, cookieName('as_session')));
    setCookie(res, cookieName('as_session'), await startAsSession(db, account.id, 'pwd'), AS_SESSION_ABSOLUTE_SECONDS);
    res.redirect(303, '/account');
  });

  router.post('/account/logout', async (req: Request, res: Response) => {
    const who = await forForm(req, res);
    if (!who) return;
    await revokeAsSession(db, who.token);
    clearCookie(res, cookieName('as_session'));
    res.redirect(303, '/account/login');
  });

  /* --------------------------------------------------- security, passkeys */

  router.get('/account', async (req: Request, res: Response) => {
    const who = await signedIn(req);
    if (!who) {
      res.redirect(303, '/account/login');
      return;
    }
    const passkeys = await listPasskeys(db, who.session.accountId);
    sendPage(res, 200, (nonce) => renderAccountPage({
      nonce, csrf: who.csrf, username: who.username, passkeys, notice: noticeFrom(req),
      error: typeof req.query.error === 'string' && req.query.error === 'password' ? 'Your current password is not right, or the new one is too short.' : undefined
    }), [], { script: true });
  });

  router.post('/account/passkeys/options', async (req: Request, res: Response) => {
    res.set('Cache-Control', 'no-store');
    const who = await signedIn(req);
    if (!who || !macMatches(who.csrf, req.body?.csrf)) {
      res.status(403).json({ error: 'Reload the page and try again.' });
      return;
    }
    if (!recent(who)) {
      res.status(403).json({ error: 'Sign in again to add a passkey.', redirect: '/account/login?reauth=1' });
      return;
    }
    res.json(await registrationOptions(db, { id: who.session.accountId, username: who.username }));
  });

  router.post('/account/passkeys', async (req: Request, res: Response) => {
    res.set('Cache-Control', 'no-store');
    const who = await signedIn(req);
    if (!who || !macMatches(who.csrf, req.body?.csrf)) {
      res.status(403).json({ error: 'Reload the page and try again.' });
      return;
    }
    if (!recent(who)) {
      res.status(403).json({ error: 'Sign in again to add a passkey.' });
      return;
    }
    const result = await finishRegistration(db, who.session.accountId, req.body?.response, req.body?.name);
    if (!result.ok) {
      res.status(400).json({ error: result.reason });
      return;
    }
    res.json({ redirect: '/account?done=passkey-added' });
  });

  router.post('/account/passkeys/:id/delete', async (req: Request, res: Response) => {
    const who = await forForm(req, res);
    if (!who) return;
    await deletePasskey(db, who.session.accountId, String(req.params.id));
    res.redirect(303, '/account?done=passkey-removed');
  });

  router.post('/account/password', async (req: Request, res: Response) => {
    const who = await forForm(req, res);
    if (!who) return;
    if (!recent(who)) {
      res.redirect(303, '/account/login?reauth=1');
      return;
    }
    try {
      await changePassword(db, who.session.accountId, req.body?.currentPassword, req.body?.newPassword);
    } catch (error) {
      if (!isAppError(error)) throw error;
      res.redirect(303, '/account?error=password');
      return;
    }
    // Every session ended, this one too. The person who just proved both
    // passwords gets a fresh one.
    setCookie(res, cookieName('as_session'), await startAsSession(db, who.session.accountId, 'pwd'), AS_SESSION_ABSOLUTE_SECONDS);
    res.redirect(303, '/account?done=password-changed');
  });

  /* -------------------------------------------------------- connected apps */

  router.get('/account/apps', async (req: Request, res: Response) => {
    const who = await signedIn(req);
    if (!who) {
      res.redirect(303, '/account/login');
      return;
    }
    const apps = await listConnectedApps(db, who.session.accountId);
    sendPage(res, 200, (nonce) => renderAppsPage({
      nonce, csrf: who.csrf, username: who.username, apps, notice: noticeFrom(req)
    }));
  });

  router.post('/account/apps/:grant/revoke', async (req: Request, res: Response) => {
    const who = await forForm(req, res);
    if (!who) return;
    await revokeConnectedApp(db, who.session.accountId, String(req.params.grant));
    res.redirect(303, '/account/apps?done=app-disconnected');
  });

  router.post('/account/signout-everywhere', async (req: Request, res: Response) => {
    const who = await forForm(req, res);
    if (!who) return;
    await signOutEverywhere(db, who.session.accountId);
    clearCookie(res, cookieName('as_session'));
    res.redirect(303, '/account/login?done=signed-out');
  });

  return router;
}
