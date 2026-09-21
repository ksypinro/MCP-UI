// Static server for the harness that also proxies /mcp to the real server,
// so the harness page and the tool calls share an origin. A real host never
// needs this: the view speaks only postMessage, and the host owns the
// connection to the server.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const dir = process.argv[2];
const UPSTREAM = process.env.BASE ?? 'http://localhost:4000';
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/mcp' && req.method === 'POST') {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const upstream = await fetch(`${UPSTREAM}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...(req.headers.authorization ? { authorization: req.headers.authorization } : {})
      },
      body: Buffer.concat(chunks)
    });
    const text = await upstream.text();
    res.writeHead(upstream.status, { 'content-type': 'application/json' }).end(text);
    return;
  }

  try {
    const file = join(dir, url.pathname === '/' ? 'host.html' : url.pathname);
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(8099, () => console.log('harness on 8099, proxying /mcp'));
