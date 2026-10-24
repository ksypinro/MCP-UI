/**
 * Profile S: every component in one process. See src/entry/ for profile M,
 * one process per component.
 */

import { createDb } from './db/index.ts';
import { createApp } from './http/app.ts';
import { pruneExpiredOAuth } from './oauth/store.ts';
import { DATABASE_PATH, PORT } from './config.ts';
import { infrastructureFromEnvironment } from './stores/index.ts';
import { log } from './observability/log.ts';
import { announce, loadKeys, onShutdown, startObservability } from './entry/common.ts';

await loadKeys();

const db = await createDb(DATABASE_PATH);
// Shared counters, proof ids, sealed responses and revocations: Redis when
// REDIS_URL is set, so several processes can serve traffic; memory otherwise.
const infra = await infrastructureFromEnvironment();
const metricsServer = startObservability();

const server = createApp(db, infra).listen(PORT, () => {
  announce('iot-switch-server', {
    listening: `:${PORT}`,
    database: process.env.DATABASE_URL ? `PostgreSQL ${new URL(process.env.DATABASE_URL).host}` : DATABASE_PATH,
    'shared state': infra.kind
  });
});

// Expired tokens, codes and pending authorizations are on the hot path of
// every protected request, so they are swept rather than left to accumulate.
const sweep = setInterval(() => {
  void pruneExpiredOAuth(db).catch((error) => {
    log('error', 'prune_failed', { error });
  });
}, 60 * 60 * 1000);
sweep.unref();

onShutdown([server, metricsServer], [() => db.close(), () => infra.close()]);
