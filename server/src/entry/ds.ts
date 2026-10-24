/**
 * Profile M: the Device Service.
 *
 * mTLS only (PORT). Accepts an internal token only over a connection made
 * with the certificate the token is bound to. Verifies tokens against the
 * authorization server's published keys (JWKS_URL).
 * Needs DATABASE_URL, JWKS_URL, TLS_*.
 */

import { createDb } from '../db/index.ts';
import { PORT } from '../config.ts';
import { useJwksUrl } from '../device-service/verify.ts';
import { deviceServiceApp } from '../split/servers.ts';
import { mtlsServer, tlsFromEnvironment } from '../split/tls.ts';
import { announce, loadKeys, onShutdown, startObservability } from './common.ts';

await loadKeys();
const jwks = process.env.JWKS_URL;
if (!jwks) throw new Error('Set JWKS_URL to the authorization server\'s /.well-known/jwks.json');
useJwksUrl(jwks);
const tls = tlsFromEnvironment();
const db = await createDb();
const metricsServer = startObservability();
const server = mtlsServer(tls, deviceServiceApp(db)).listen(PORT);
announce('iot-switch Device Service', { listening: `:${PORT} (mTLS)` });
onShutdown([server, metricsServer], [() => db.close()]);
