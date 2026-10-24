/**
 * Mutual TLS between the components of profile M. Plan 4.7.
 *
 * Every internal connection is TLS in both directions, against a private CA.
 * A peer is identified by the SPIFFE-style URI in its certificate
 * (spiffe://iot-switch/<workload>), never by its address, and checked
 * against the list of workloads allowed to call that endpoint. Certificates
 * are read from files, which a service mesh rotates in place.
 */

import { readFileSync } from 'node:fs';
import { Agent, request, createServer, type Server } from 'node:https';
import type { TLSSocket } from 'node:tls';
import type { RequestListener } from 'node:http';
import { certificateWorkload, workloadNamed, type Workload, type WorkloadName } from '../security/workload.ts';

export interface TlsFiles {
  cert: Buffer;
  key: Buffer;
  ca: Buffer;
}

/** TLS_CERT, TLS_KEY and TLS_CA: this process's certificate, its key, and the CA every peer must chain to. */
export function tlsFromEnvironment(): TlsFiles {
  const { TLS_CERT, TLS_KEY, TLS_CA } = process.env;
  if (!TLS_CERT || !TLS_KEY || !TLS_CA) throw new Error('Set TLS_CERT, TLS_KEY and TLS_CA for internal mTLS');
  return { cert: readFileSync(TLS_CERT), key: readFileSync(TLS_KEY), ca: readFileSync(TLS_CA) };
}

/** An HTTPS server that refuses any client without a certificate from the CA. */
export function mtlsServer(tls: TlsFiles, handler: RequestListener): Server {
  return createServer({
    cert: tls.cert, key: tls.key, ca: tls.ca,
    requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3'
  }, handler);
}

/** The workload on the other end of this connection, if it is one of `allowed`. */
export function peerWorkload(socket: TLSSocket, allowed: readonly WorkloadName[]): Workload | null {
  if (!socket.authorized) return null;
  const certificate = socket.getPeerCertificate();
  if (!certificate?.raw) return null;
  const uris = (certificate.subjectaltname ?? '').split(/,\s*/)
    .filter((entry) => entry.startsWith('URI:')).map((entry) => entry.slice(4));
  // Exactly one identity per certificate: a certificate claiming two
  // workloads is not trusted as either.
  const names = uris.map(workloadNamed).filter((name): name is WorkloadName => name !== null);
  if (uris.length !== 1 || names.length !== 1) return null;
  const name = names[0]!;
  return allowed.includes(name) ? certificateWorkload(name, certificate.raw) : null;
}

/** A client agent presenting this process's certificate, trusting only the CA. */
export function mtlsAgent(tls: TlsFiles): Agent {
  return new Agent({ cert: tls.cert, key: tls.key, ca: tls.ca, keepAlive: true, minVersion: 'TLSv1.3' });
}

/** The workload this process is, read from its own certificate. */
export function ownWorkload(tls: TlsFiles, name: WorkloadName): Workload {
  const pem = tls.cert.toString('utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0];
  if (!pem) throw new Error('TLS_CERT holds no certificate');
  const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
  return certificateWorkload(name, der);
}

export interface JsonResponse { status: number; body: any }

/** POSTs JSON over mTLS. Times out rather than hanging a request behind a dead peer. */
export function postJson(
  agent: Agent, url: string, body: unknown, headers: Record<string, string> = {}, timeoutMs = 2_000
): Promise<JsonResponse> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = request(url, {
      method: 'POST', agent, timeout: timeoutMs,
      headers: { 'content-type': 'application/json', 'content-length': String(payload.length), ...headers }
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: unknown = null;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs} ms`)));
    req.on('error', reject);
    req.end(payload);
  });
}
