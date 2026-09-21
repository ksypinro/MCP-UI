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
import { MCP_PATH, SERVER_INFO } from './config.ts';
import { gate } from './gate.ts';
import { registerDeviceTools } from './tools.ts';
import type { Identity } from '../domain/types.ts';

function buildServer(db: Db, identity: Identity | null): McpServer {
  const server = new McpServer(SERVER_INFO, {
    capabilities: { tools: {}, resources: {} }
  });
  registerDeviceTools(server, db, identity);
  return server;
}

export function mcpRoutes(db: Db): Router {
  const router = Router();

  router.post(MCP_PATH, async (req: Request, res: Response) => {
    const requestId = context(res)?.requestId ?? 'req_mcp';

    // Before the SDK sees anything. A refusal has to be an HTTP status.
    const outcome = await gate(db, req, res, requestId);
    if (!outcome.proceed) return;

    // Stateless: one server and transport per request, so a connection can
    // change identity between calls without carrying the previous one's
    // devices. The host holds the session, not us.
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    res.on('close', () => { void transport.close(); });

    const server = buildServer(db, outcome.identity);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // A stateless server has no stream to resume and no session to delete.
  router.get(MCP_PATH, (_req, res) => { res.status(405).set('Allow', 'POST').end(); });
  router.delete(MCP_PATH, (_req, res) => { res.status(405).set('Allow', 'POST').end(); });

  return router;
}
