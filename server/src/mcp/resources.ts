import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  ADD_DEVICE_URI, AUTH_URI, UI_MIME, uiResourceMeta, uiResources, uiToolMeta
} from './ui/index.ts';

/**
 * Registers the UI resources and the two tools whose only job is to present
 * one. Spec sections 8.2 and 9.1.
 *
 * Both presentation tools are public. Gating a form's *display* behind a write
 * scope means merely showing it can trigger a 403 and a re-consent prompt
 * before the person has typed anything; the tool the form then calls is where
 * authorization belongs.
 */
export function registerUi(server: McpServer): void {
  for (const resource of uiResources()) {
    server.registerResource(
      resource.name,
      resource.uri,
      {
        title: resource.title,
        description: resource.description,
        mimeType: UI_MIME,
        _meta: uiResourceMeta()
      },
      async (uri) => ({
        contents: [{ uri: uri.href, mimeType: UI_MIME, text: resource.html }]
      })
    );
  }

  server.registerTool(
    'show_auth',
    {
      title: 'Show sign-in',
      description:
        'Display the sign-up / log-in entry card. Public, and performs no authentication '
        + 'itself: the card asks the host to authorize when the person chooses to.',
      inputSchema: {
        mode: z.enum(['login', 'signup']).optional()
          .describe('Which option to lead with. The card offers both regardless.')
      },
      outputSchema: { mode: z.enum(['login', 'signup']), authenticated: z.boolean() },
      annotations: {
        readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false
      },
      _meta: uiToolMeta(AUTH_URI)
    },
    async ({ mode }) => ({
      content: [{ type: 'text', text: 'Sign in to IoT Switch to see and control your devices.' }],
      // Deliberately says nothing about who is signed in: this tool is public,
      // and its result is model-visible.
      structuredContent: { mode: mode ?? 'login', authenticated: false }
    })
  );

  server.registerTool(
    'show_add_device',
    {
      title: 'Show the add-device form',
      description:
        'Display a form for adding a device. Presentation only: it creates nothing until the '
        + 'person submits it, which calls add_device.',
      inputSchema: {},
      outputSchema: { ready: z.boolean() },
      annotations: {
        readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false
      },
      _meta: uiToolMeta(ADD_DEVICE_URI)
    },
    async () => ({
      content: [{ type: 'text', text: 'Enter a name for the new device. It will start Off.' }],
      structuredContent: { ready: true }
    })
  );
}
