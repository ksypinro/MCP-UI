/**
 * A local CA and workload certificates for profile M.
 *
 *   npm run certs -- <directory>
 *
 * Uses the openssl command line. Each certificate carries one SPIFFE URI
 * naming its workload, and DNS names for the host it serves on. For testing
 * and the reference compose file only: in production a service mesh issues
 * and rotates these.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface Issued { cert: string; key: string }

function openssl(cwd: string, ...args: string[]): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

export function makeCa(dir: string, name = 'ca'): Issued {
  mkdirSync(dir, { recursive: true });
  openssl(dir, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.crt`, '-days', '30', '-subj', `/CN=iot-switch ${name}`);
  return { cert: join(dir, `${name}.crt`), key: join(dir, `${name}.key`) };
}

/** A certificate for `spiffeUri` (or none), valid for `dnsNames`, signed by `ca`. */
export function issue(dir: string, ca: Issued, name: string, spiffeUris: string[], dnsNames: string[] = ['localhost']): Issued {
  openssl(dir, 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`);
  const san = [...spiffeUris.map((uri) => `URI:${uri}`), ...dnsNames.map((dns) => `DNS:${dns}`), 'IP:127.0.0.1'].join(',');
  writeFileSync(join(dir, `${name}.ext`), `subjectAltName=${san}\nextendedKeyUsage=clientAuth,serverAuth\n`);
  openssl(dir, 'x509', '-req', '-in', `${name}.csr`, '-CA', ca.cert, '-CAkey', ca.key, '-CAcreateserial',
    '-out', `${name}.crt`, '-days', '30', '-extfile', `${name}.ext`);
  return { cert: join(dir, `${name}.crt`), key: join(dir, `${name}.key`) };
}

/** The set the compose file and the end-to-end test use. */
export interface ProfileMCertificates {
  ca: Issued; auth: Issued; 'device-service': Issued; 'mcp-rs': Issued; 'api-gw': Issued;
}

export function makeProfileMCertificates(dir: string): ProfileMCertificates {
  const ca = makeCa(dir);
  return {
    ca,
    auth: issue(dir, ca, 'auth', ['spiffe://iot-switch/auth'], ['localhost', 'as']),
    'device-service': issue(dir, ca, 'device-service', ['spiffe://iot-switch/device-service'], ['localhost', 'ds']),
    'mcp-rs': issue(dir, ca, 'mcp-rs', ['spiffe://iot-switch/mcp-rs'], ['localhost', 'rs']),
    'api-gw': issue(dir, ca, 'api-gw', ['spiffe://iot-switch/api-gw'], ['localhost', 'gw'])
  };
}

if (import.meta.main) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write('usage: npm run certs -- <directory>\n');
    process.exit(2);
  }
  makeProfileMCertificates(dir);
  process.stdout.write(`certificates written to ${dir}\n`);
}
