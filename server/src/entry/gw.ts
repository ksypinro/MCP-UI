/**
 * Profile M: the REST API gateway. Plan 4.7.
 * Needs AUTH_INTERNAL_URL, DEVICE_SERVICE_URL, REDIS_URL, TLS_* (an api-gw certificate).
 * The legacy password endpoints are retired here: the gateway has no database.
 */

import { PORT } from '../config.ts';
import { apiRouter, baseApp, finishApp } from '../http/app.ts';
import { announce, loadKeys, onShutdown, startObservability } from './common.ts';
import { edgeDeps } from './edge.ts';

await loadKeys();
const deps = await edgeDeps('api-gw');
const metricsServer = startObservability();
const app = baseApp();
app.use(apiRouter(deps, null));
const server = finishApp(app).listen(PORT);
announce('iot-switch API gateway', { listening: `:${PORT}`, 'shared state': deps.infra.kind });
onShutdown([server, metricsServer], [() => deps.infra.close()]);
