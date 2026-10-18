/**
 * Stands in for a person at a browser, for the dev harnesses: starts at an
 * authorization URL, signs up on the hosted page, approves on the consent
 * page, and returns the callback URL the server redirects to.
 *
 * It keeps the two cookies the pages rely on — the browser binding and the
 * authorization-server session — because every step after the first refuses
 * a browser that does not carry them.
 */

export async function signUpAndApprove(authorizationUrl, { username, password = 'correct horse battery staple' }) {
  const start = new URL(authorizationUrl);
  const origin = start.origin;
  const cookies = new Map();

  async function go(url, init = {}) {
    const headers = new Headers(init.headers);
    if (cookies.size) headers.set('cookie', [...cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    const response = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const line of response.headers.getSetCookie()) {
      const [pair] = line.split(';');
      const index = pair.indexOf('=');
      const value = pair.slice(index + 1).trim();
      if (value) cookies.set(pair.slice(0, index).trim(), value);
      else cookies.delete(pair.slice(0, index).trim());
    }
    return response;
  }

  /** Follows redirects on our own origin; stops at the first one leaving it. */
  async function follow(response) {
    for (let hops = 0; hops < 10; hops++) {
      const location = response.headers.get('location');
      if (response.status < 300 || response.status >= 400 || !location) return { response };
      const next = new URL(location, origin);
      if (next.origin !== origin) return { callback: next };
      response = await go(next);
    }
    throw new Error('too many redirects');
  }

  const post = (path, fields) => go(new URL(path, origin), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields)
  });

  let step = await follow(await go(start));
  for (let round = 0; round < 4; round++) {
    if (step.callback) return step.callback;
    const html = await step.response.text();
    const pending = html.match(/name="pending" value="([^"]+)"/)?.[1];
    const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
    if (!pending || !csrf) throw new Error(`the authorization page did not render a form (${step.response.status})`);

    if (html.includes('action="/login"')) {
      step = await follow(await post('/login', { pending, csrf, mode: 'signup', username, password }));
    } else if (html.includes('action="/consent"')) {
      step = await follow(await post('/consent', { pending, csrf }));
    } else {
      throw new Error('an authorization page this harness does not understand');
    }
  }
  throw new Error('authorization did not finish');
}
