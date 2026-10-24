/**
 * Start-up shared by every entry point: key material, metrics, alerts, and
 * an orderly shutdown.
 */

import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { DATABASE_PATH } from '../config.ts';
import { keys, useKeyFile, useKeyMaterial } from '../security/keys.ts';
import { kmsFromEnvironment, openEnvelope } from '../security/kms.ts';
import { log } from '../observability/log.ts';
import { metrics } from '../observability/metrics.ts';
import { startAlerts } from '../observability/alerts.ts';

/**
 * Key material. With KMS_PROVIDER, an envelope file decrypted through the KMS
 * (signing keys stay inside it); otherwise the environment, or a plain key
 * file beside the database. Every process of one deployment must load the
 * same material: the DPoP nonce and the token hashes depend on it. Loaded
 * now, so a bad configuration stops the process at start-up.
 */
export async function loadKeys(): Promise<void> {
  const kms = kmsFromEnvironment(join(DATABASE_PATH, 'local-kms.json'));
  if (kms) {
    useKeyMaterial(await openEnvelope(kms, process.env.KMS_KEY_FILE ?? join(DATABASE_PATH, 'keys.kms.json')));
    if (kms.name === 'local' && process.env.NODE_ENV === 'production') {
      log('warn', 'local_kms_in_production', { detail: 'KMS_PROVIDER=local keeps its key-encryption key on this disk: no better than a key file' });
    }
  } else if (!process.env.TOKEN_PEPPERS) {
    useKeyFile(join(DATABASE_PATH, 'keys.json'));
  }
  keys();
}

/** Alerts, and metrics on their own listener (METRICS_PORT), loopback by default. */
export function startObservability(): Server | null {
  startAlerts();
  const port = process.env.METRICS_PORT ? Number(process.env.METRICS_PORT) : null;
  if (port === null) return null;
  return createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/metrics') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' }).end(metrics.render());
  }).listen(port, process.env.METRICS_HOST ?? '127.0.0.1');
}

/** Closes `servers`, then `resources`, on SIGINT or SIGTERM. */
export function onShutdown(servers: Array<{ close(cb?: () => void): unknown } | null>, resources: Array<() => Promise<unknown>>): void {
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      let open = servers.filter(Boolean).length;
      const done = () => { void Promise.all(resources.map((close) => close())).then(() => process.exit(0)); };
      if (open === 0) return done();
      for (const server of servers) server?.close(() => { if (--open === 0) done(); });
    });
  }
}

export function announce(name: string, lines: Record<string, string>): void {
  process.stdout.write(`${name}\n${Object.entries(lines).map(([k, v]) => `  ${k} ${v}`).join('\n')}\n`);
}
