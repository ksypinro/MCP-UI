/**
 * Universal links for the app's sign-in callback.
 *
 * The app's preferred redirect URI is an https URL on this host. iOS hands it
 * to the app only if this host publishes an apple-app-site-association file
 * naming the app — which another app cannot do for our domain, unlike a
 * custom URL scheme anyone can register. The file needs the Apple team id
 * (APPLE_TEAM_ID); without it nothing is published and the app uses its
 * development scheme instead.
 *
 * If the link is opened somewhere the app is not installed, the browser lands
 * on /oauth/callback here. That page says so and nothing more: it never
 * echoes the code, and the code is useless without the app's PKCE verifier
 * and DPoP key anyway.
 */

import { Router } from 'express';
import { authPageHeaders, newNonce } from '../security/headers.ts';
import { renderErrorPage } from '../oauth/pages.ts';

export function appLinkRoutes(): Router {
  const router = Router();

  router.get('/.well-known/apple-app-site-association', (_req, res, next) => {
    const team = process.env.APPLE_TEAM_ID;
    if (!team) return next(); // falls through to 404
    const appId = `${team}.${process.env.APPLE_BUNDLE_ID ?? 'com.example.IoTSwitch'}`;
    res.type('application/json').set('Cache-Control', 'public, max-age=3600').send(JSON.stringify({
      applinks: { details: [{ appIDs: [appId], components: [{ '/': '/oauth/callback', comment: 'Sign-in callback' }] }] },
      webcredentials: { apps: [appId] }
    }));
  });

  router.get('/oauth/callback', (_req, res) => {
    const nonce = newNonce();
    authPageHeaders(res, { nonce });
    res.status(200).type('html').send(renderErrorPage(
      'Open the IoT Switch app',
      'This sign-in finishes in the IoT Switch app. Open the app on this device to continue.',
      nonce
    ));
  });

  return router;
}
