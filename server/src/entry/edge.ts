/**
 * What the two edge processes of profile M share: no database, callers
 * verified by introspection, internal tokens by exchange, devices through
 * the Device Service, all over mTLS with this process's workload certificate.
 */

import { infrastructureFromEnvironment, type Infrastructure } from '../stores/index.ts';
import { ExchangeClient } from '../exchange-client.ts';
import { WriteBudgets } from '../write-budgets.ts';
import type { EdgeDeps } from '../http/app.ts';
import type { WorkloadName } from '../security/workload.ts';
import { mtlsAgent, ownWorkload, tlsFromEnvironment } from '../split/tls.ts';
import { remoteDeviceService, remoteExchanger, remoteVerifier } from '../split/remote.ts';

export async function edgeDeps(name: WorkloadName): Promise<EdgeDeps & { infra: Infrastructure }> {
  const authUrl = process.env.AUTH_INTERNAL_URL;
  const deviceUrl = process.env.DEVICE_SERVICE_URL;
  if (!authUrl || !deviceUrl) throw new Error('Set AUTH_INTERNAL_URL and DEVICE_SERVICE_URL');
  const tls = tlsFromEnvironment();
  const agent = mtlsAgent(tls);
  const workload = ownWorkload(tls, name);
  const infra = await infrastructureFromEnvironment();
  return {
    infra,
    verifier: remoteVerifier(authUrl, agent, infra.revocations),
    exchange: new ExchangeClient(workload, remoteExchanger(authUrl, agent), infra.revocations),
    devices: remoteDeviceService(deviceUrl, agent),
    budgets: new WriteBudgets(infra.buckets)
  };
}
