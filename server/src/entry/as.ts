/**
 * Profile M: the authorization server.
 *
 * Public: OAuth, the hosted sign-in and account pages, JWKS (PORT).
 * Internal, mTLS only: introspection and token exchange (INTERNAL_PORT).
 * Needs DATABASE_URL, REDIS_URL, TLS_CERT/TLS_KEY/TLS_CA.
 */

import { createDb } from '../db/index.ts';
import { authServerRouter, baseApp, finishApp } from '../http/app.ts';
import { pruneExpiredOAuth } from '../oauth/store.ts';
import { PORT } from '../config.ts';
import { infrastructureFromEnvironment } from '../stores/index.ts';
import { internalAuthApp } from '../split/servers.ts';
import { mtlsServer, tlsFromEnvironment } from '../split/tls.ts';
import { log } from '../observability/log.ts';
import { announce, loadKeys, onShutdown, startObservability } from './common.ts';

await loadKeys();
const tls = tlsFromEnvironment();
const db = await createDb();
const infra = await infrastructureFromEnvironment();
const metricsServer = startObservability();

const app = baseApp();
app.use(authServerRouter(db, infra));
const server = finishApp(app).listen(PORT);

const internalPort = Number(process.env.INTERNAL_PORT ?? 9443);
const internal = mtlsServer(tls, internalAuthApp(db)).listen(internalPort);

const sweep = setInterval(() => {
  void pruneExpiredOAuth(db).catch((error) => log('error', 'prune_failed', { error }));
}, 60 * 60 * 1000);
sweep.unref();

announce('iot-switch authorization server', { public: `:${PORT}`, internal: `:${internalPort} (mTLS)`, 'shared state': infra.kind });
onShutdown([server, internal, metricsServer], [() => db.close(), () => infra.close()]);
