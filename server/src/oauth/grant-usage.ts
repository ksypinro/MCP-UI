/**
 * When each grant was last used, for the connected-apps page (plan 4.6).
 */

import type { Queryable } from '../db/index.ts';

/**
 * Records that a grant was used, at most once a minute per grant per
 * process, so the connected-apps page can say when an app last did anything
 * without a write on every request.
 */
const lastTouched = new Map<string, number>();

export async function touchGrant(db: Queryable, grantId: string): Promise<void> {
  const now = Date.now();
  const previous = lastTouched.get(grantId);
  if (previous !== undefined && now - previous < 60_000) return;
  lastTouched.set(grantId, now);
  if (lastTouched.size > 50_000) {
    for (const [id, at] of lastTouched) if (now - at >= 60_000) lastTouched.delete(id);
  }
  await db.query(
    `UPDATE oauth_grants SET last_used_at = now()
      WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`,
    [grantId]
  );
}
