import { createDb, type Db } from '../src/db/index.ts';
import { createAccount } from '../src/domain/accounts.ts';
import type { Identity } from '../src/domain/types.ts';

/** A fresh in-memory database per call. No data dir, so nothing leaks between tests. */
export async function freshDb(): Promise<Db> {
  return createDb();
}

let seq = 0;

export async function makeIdentity(db: Db, channel: Identity['channel'] = 'native'): Promise<Identity> {
  const account = await createAccount(db, `tester${++seq}`, 'correct horse battery staple');
  return { accountId: account.id, channel, requestId: `req_test_${seq}` };
}

/** Asserts that `fn` rejects with an AppError carrying `code`. */
export async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    const actual = (error as { code?: string }).code;
    if (actual === code) return;
    throw new Error(`expected error code ${code}, got ${actual ?? String(error)}`);
  }
  throw new Error(`expected error code ${code}, but the call resolved`);
}
