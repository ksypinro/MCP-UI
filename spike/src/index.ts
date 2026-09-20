/**
 * Phase 0 spike entry point.
 *
 * The whole reason this file exists rather than letting the MCP SDK own the
 * route: an unauthenticated protected call must fail as an HTTP 401 with a
 * WWW-Authenticate challenge. Once a tool handler is running, its return value
 * is already destined for a 200, and a 200 carrying isError is an application
 * error that no host treats as an authentication signal. So the gate runs on
 * the parsed body, before transport.handleRequest.
 */

import express, { type Request, type Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { BASE_URL, PORT, PROTECTED_TOOLS, RESOURCE_URI, SCOPES } from './config.js';
import { oauthRouter } from './oauth.js';
import { buildMcpServer } from './mcp.js';
import { readAccessToken, type AccessToken } from './store.js';

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(oauthRouter);

const PRM_URL = `${BASE_URL}/.well-known/oauth-protected-resource/mcp`;

function bearer(req: Request): string | null {
  const header = req.get('authorization');
  if (!header?.toLowerCase().startsWith('bearer ')) return null;
  return header.slice(7).trim() || null;
}

/**
 * Returns the tool name if this body calls a protected tool. Handles batched
 * requests, because a batch containing one protected call must still challenge.
 */
function protectedToolIn(body: unknown): string | null {
  for (const message of Array.isArray(body) ? body : [body]) {
    if (!message || typeof message !== 'object') continue;
    const { method, params } = message as { method?: unknown; params?: { name?: unknown } };
    if (method !== 'tools/call') continue;
    const name = params?.name;
    if (typeof name === 'string' && Object.hasOwn(PROTECTED_TOOLS, name)) return name;
  }
  return null;
}

function challenge(res: Response, error: string, scope: string, status: 401 | 403, description: string): void {
  res
    .status(status)
    .set(
      'WWW-Authenticate',
      `Bearer error="${error}", error_description="${description}", ` +
        `resource_metadata="${PRM_URL}", scope="${scope}"`
    )
    .json({ error, error_description: description });
}

app.post('/mcp', async (req: Request, res: Response) => {
  const token = readAccessToken(bearer(req));

  // A token minted for a different resource must never be accepted here,
  // however valid it is elsewhere.
  let auth: AccessToken | null = null;
  if (token) {
    if (token.aud === RESOURCE_URI) {
      auth = token;
    } else {
      // Silently treating this as "signed out" produces an endless
      // authorize/401/authorize loop that looks exactly like a user who never
      // logged in. Usually it means BASE_URL and the registered connector URL
      // disagree about a trailing slash or a hostname.
      process.stderr.write(
        `[auth] rejecting token for audience ${token.aud}; this server is ${RESOURCE_URI}\n`
      );
    }
  }

  const wanted = protectedToolIn(req.body);
  if (wanted) {
    if (!auth) {
      // 401, never 200 + isError: only a transport-level 401 makes a host
      // pause the call, run OAuth, and retry it.
      challenge(res, 'invalid_token', SCOPES.join(' '), 401, 'Authentication required for this tool');
      return;
    }
    const required = PROTECTED_TOOLS[wanted];
    if (required && !auth.scopes.includes(required)) {
      // Step-up: name every scope the operation needs, not just the missing
      // one, or the client may drop permissions it already had.
      challenge(res, 'insufficient_scope', SCOPES.join(' '), 403, `Scope ${required} is required`);
      return;
    }
  }

  // initialize, tools/list, resources/read and the public tools fall through.
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true
  });
  res.on('close', () => void transport.close());

  const server = buildMcpServer(auth);
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// Streamable HTTP clients may probe these; a stateless server has no stream to
// resume and no session to delete.
app.get('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
app.delete('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());

// Without this, Express's default handler returns the stack trace, and the
// spike spends its life on a public tunnel URL.
app.use((error: unknown, req: Request, res: Response, _next: express.NextFunction) => {
  const requestId = Math.random().toString(36).slice(2, 10);
  process.stderr.write(`[error] ${requestId} ${req.method} ${req.path} ${String(error)}\n`);
  if (res.headersSent) return;
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Unexpected error.', requestId } });
});

app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IoT Switch — phase 0 spike</title>
<style>body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#141413}
code{background:#f5f4ed;padding:.15em .4em;border-radius:4px;font-size:.9em}</style>
<h1>IoT Switch — phase 0 spike</h1>
<p>Throwaway host-feasibility spike. Not the product.</p>
<p>MCP endpoint: <code>${RESOURCE_URI}</code></p>
<p>Add that URL as a custom connector, then ask the assistant to sign in to IoT Switch.</p>`);
});

app.listen(PORT, () => {
  process.stdout.write(
    `iot-switch-spike listening on :${PORT}\n` +
      `  base url   ${BASE_URL}\n` +
      `  mcp        ${RESOURCE_URI}\n` +
      `  prm        ${PRM_URL}\n` +
      (BASE_URL.startsWith('http://localhost')
        ? '  note       hosts cannot reach localhost. Tunnel it and set BASE_URL to the tunnel origin.\n'
        : '')
  );
});
