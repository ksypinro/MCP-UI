/**
 * Adds `securitySchemes` to every tool in `tools/list`.
 *
 * ChatGPT decides whether a tool needs account linking from this field, and
 * starts linking only for tools that declare it. `McpServer.registerTool`
 * accepts `_meta` but not arbitrary top-level fields, so the scheme is written
 * in both places: `_meta.securitySchemes`, which any client may read, and the
 * top level, where the Apps SDK documents it. Other hosts ignore both.
 *
 * Writing the top level means wrapping the SDK's own `tools/list` handler,
 * which is not public API. `test/mcp.test.ts` pins this: an SDK upgrade that
 * moves the handler fails that test rather than silently dropping the field.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { securitySchemesFor } from './config.ts';

type Handler = (request: unknown, extra: unknown) => Promise<unknown>;

export function exposeSecuritySchemes(server: McpServer): void {
  const handlers = (server.server as unknown as { _requestHandlers?: Map<string, Handler> })._requestHandlers;
  const original = handlers?.get('tools/list');
  if (!handlers || !original) {
    throw new Error('MCP SDK internals changed: no tools/list handler to extend');
  }

  handlers.set('tools/list', async (request, extra) => {
    const result = await original(request, extra) as { tools: Array<Record<string, unknown>> };
    return {
      ...result,
      tools: result.tools.map((tool) => {
        const schemes = securitySchemesFor(String(tool.name));
        const meta = (tool._meta ?? {}) as Record<string, unknown>;
        return { ...tool, securitySchemes: schemes, _meta: { ...meta, securitySchemes: schemes } };
      })
    };
  });
}
