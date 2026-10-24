/**
 * The MCP endpoint.
 *
 * Mounted at exactly /mcp because that path is the canonical resource URI
 * published in the protected resource metadata and bound into every token's
 * audience. It is not a free choice.
 */

import { Router, type Request, type Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Db } from '../db/index.ts';
import { context } from '../http/middleware.ts';
import { bucket } from '../security/rate-limit.ts';
import { MCP_PATH, SERVER_INFO } from './config.ts';
import { gate, type GateLimits } from './gate.ts';
import { registerDeviceTools, type ToolDeps } from './tools.ts';
import { registerUi } from './resources.ts';
import { exposeSecuritySchemes } from './security-schemes.ts';
import { protectedResourceMetadataRouter } from '../oauth/metadata.ts';
import type { Caller } from '../domain/types.ts';

function buildServer(deps: ToolDeps, caller: Caller, challenge: string | undefined): McpServer {
  const server = new McpServer(SERVER_INFO, {
    capabilities: { tools: {}, resources: {} }
  });
  registerDeviceTools(server, deps, caller, challenge);
  registerUi(server);
  exposeSecuritySchemes(server);
  return server;
}

export function mcpRoutes(deps: ToolDeps): Router {
  const { verifier } = deps;
  const router = Router();

  // Protected resource metadata belongs to the resource, so it is served from
  // the MCP origin the 401 challenge points at.
  router.use(protectedResourceMetadataRouter);

  // Discovery has to work without a token, which makes it the one part of
  // this endpoint an attacker can drive without an account — and each request
  // builds a server and compiles five schemas. So traffic without a verified
  // token is bounded by address.
  //
  // Traffic with a verified token is bounded by grant instead. A host calls
  // this from its own infrastructure on behalf of every one of its users, so
  // an address-keyed limit would throttle all of them together the moment the
  // integration became popular. The gate picks between the two only after it
  // has verified the token; see gate.ts.
  const store = deps.infra.buckets;
  const limits: GateLimits = {
    perAddress: bucket(store, 60, 60_000),
    perGrant: bucket(store, 600, 60_000),
    replay: deps.infra.replay
  };

  router.post(MCP_PATH, async (req: Request, res: Response) => {
    const requestId = context(res)?.requestId ?? 'req_mcp';

    // Before the SDK sees anything. A refusal has to be an HTTP status.
    const outcome = await gate(verifier, req, res, requestId, limits);
    if (!outcome.proceed) return;

    // Stateless: one server and transport per request, so a connection can
    // change identity between calls without carrying the previous one's
    // devices. The host holds the session, not us.
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    res.on('close', () => { void transport.close(); });

    const server = buildServer(deps, outcome.caller, outcome.challenge);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // A stateless server has no stream to resume and no session to delete.
  router.get(MCP_PATH, (_req, res) => { res.status(405).set('Allow', 'POST').end(); });
  router.delete(MCP_PATH, (_req, res) => { res.status(405).set('Allow', 'POST').end(); });

  return router;
}
