/**
 * The MCP endpoint.
 *
 * Mounted at exactly /mcp because that path is the canonical resource URI
 * published in the protected resource metadata and bound into every token's
 * audience. It is not a free choice.
 */

import { createHash } from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Db } from '../db/index.ts';
import { context, rateLimit } from '../http/middleware.ts';
import { MCP_PATH, SERVER_INFO } from './config.ts';
import { bearerFrom, gate } from './gate.ts';
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

  // Discovery has to work without a token, which makes it the one part of
  // this endpoint an attacker can drive without an account — and each request
  // builds a server and compiles five schemas. So anonymous traffic is
  // bounded by address.
  //
  // Authenticated traffic is bounded by token instead. A host calls this from
  // its own infrastructure on behalf of every one of its users, so an
  // address-keyed limit would throttle all of them together the moment the
  // integration became popular.
  const anonymousLimiter = rateLimit(60, 60_000, (req) => `mcp-anon:${req.ip ?? 'unknown'}`);
  const tokenLimiter = rateLimit(600, 60_000, (req) => {
    const token = bearerFrom(req) ?? '';
    return `mcp-token:${createHash('sha256').update(token).digest('hex')}`;
  });

  router.post(MCP_PATH, (req: Request, res: Response, next: NextFunction) => {
    (bearerFrom(req) ? tokenLimiter : anonymousLimiter)(req, res, next);
  });

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
