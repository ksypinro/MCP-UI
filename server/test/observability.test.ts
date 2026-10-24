/**
 * The logger, the security metrics and the alerts. Plan 4.8.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { log, scrub, useLogSink } from '../src/observability/log.ts';
import { metrics } from '../src/observability/metrics.ts';
import { startAlerts } from '../src/observability/alerts.ts';
import { mint } from '../src/tokens/format.ts';
import { authorizeAs, exchange, json, startServer, type Harness } from './oauth-helpers.ts';

const lines: string[] = [];
useLogSink((line) => lines.push(line));
startAlerts();

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

test('logging a request with an Authorization header writes no token', () => {
  const token = mint('access');
  const request = { method: 'GET', headers: { authorization: `Bearer ${token}`, cookie: 'as_session=x' } };
  const before = metrics.value('log_fields_dropped');

  log('error', 'request failed', { request, headers: request.headers, requestId: 'req_1' });
  log('error', `failed for ${token}`, { detail: `presented Bearer ${token}`, error: new Error(`token ${token} refused`) });

  const written = lines.slice(-2).join('\n');
  assert.ok(!written.includes(token.slice(9)), 'no part of the token after its prefix appears');
  assert.ok(written.includes('"requestId":"req_1"'), 'allowlisted fields still appear');
  assert.ok(!written.includes('cookie'), 'the request object and its headers are dropped whole');
  assert.equal(metrics.value('log_fields_dropped') - before, 2);
});

test('the scanner replaces every kind of token and counts each one', () => {
  const before = metrics.value('log_secrets_redacted');
  const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhY2NfMSJ9.c2lnbmF0dXJlc2lnbmF0dXJl';
  const out = scrub(`a=${mint('refresh')} b=${mint('code')} c=${jwt} d=DPoP abcdefghijklmnop`);
  assert.equal(out, 'a=iotsw_[redacted] b=iotsw_[redacted] c=[redacted-jwt] d=DPoP [redacted]');
  assert.equal(metrics.value('log_secrets_redacted') - before, 4);
});

test('refresh outcomes are counted, and theft raises an alert', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  const refresh = (token: string) => fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: token, client_id: authorization.clientId
  }));
  const rotated = metrics.value('refresh_rotated');
  const replayed = metrics.value('refresh_grace_replay');
  const theft = metrics.value('refresh_theft_detected');

  const second = await (await refresh(first.body.refresh_token!)).json() as { refresh_token: string };
  await refresh(first.body.refresh_token!);                 // inside the window: the sealed copy
  await refresh(second.refresh_token);                      // the successor is used...
  await refresh(first.body.refresh_token!);                 // ...so the original coming back is theft

  assert.equal(metrics.value('refresh_rotated') - rotated, 2);
  assert.equal(metrics.value('refresh_grace_replay') - replayed, 1);
  assert.equal(metrics.value('refresh_theft_detected') - theft, 1);
  assert.ok(lines.some((line) => line.includes('"level":"alert"') && line.includes('refresh_token_theft')));
});

test('a burst of replayed DPoP proofs raises one alert', () => {
  const alertsBefore = metrics.value('alerts_raised', { alert: 'dpop_replay_burst' });
  for (let i = 0; i < 15; i++) metrics.inc('dpop_rejected', { reason: 'replay' });
  assert.equal(metrics.value('alerts_raised', { alert: 'dpop_replay_burst' }) - alertsBefore, 1, 'one alert per minute, not fifteen');
});

test('the metrics render in the Prometheus text format', () => {
  metrics.inc('cimd_fetch', { result: 'denied_range' });
  const text = metrics.render();
  assert.match(text, /# TYPE iotsw_refresh_rotated_total counter/);
  assert.match(text, /iotsw_dpop_rejected_total\{reason="replay"\} \d+/);
  assert.match(text, /iotsw_cimd_fetch_total\{result="denied_range"\} \d+/);
  assert.ok(lines.some((line) => line.includes('cimd_denied_range')), 'a denied-range fetch raises an alert');
});
