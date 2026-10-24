/**
 * Profile M: the MCP resource server.
 * Needs AUTH_INTERNAL_URL, DEVICE_SERVICE_URL, REDIS_URL, TLS_* (an mcp-rs certificate).
 */

import { PORT } from '../config.ts';
import { baseApp, finishApp } from '../http/app.ts';
import { mcpRoutes } from '../mcp/routes.ts';
import { announce, loadKeys, onShutdown, startObservability } from './common.ts';
import { edgeDeps } from './edge.ts';

await loadKeys();
const deps = await edgeDeps('mcp-rs');
const metricsServer = startObservability();
const app = baseApp();
app.use(mcpRoutes(deps));
const server = finishApp(app).listen(PORT);
announce('iot-switch MCP resource server', { listening: `:${PORT}`, 'shared state': deps.infra.kind });
onShutdown([server, metricsServer], [() => deps.infra.close()]);
