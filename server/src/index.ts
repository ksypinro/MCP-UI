import { createDb } from './db/index.ts';
import { createApp } from './http/app.ts';
import { pruneExpired } from './domain/sessions.ts';
import { pruneExpiredOAuth } from './oauth/store.ts';
import { DATABASE_PATH, PORT } from './config.ts';

const db = await createDb(DATABASE_PATH);
const app = createApp(db);

const server = app.listen(PORT, () => {
  process.stdout.write(`iot-switch-server listening on :${PORT}\n  database ${DATABASE_PATH}\n`);
});

// Expired sessions and access tokens are on the hot path of every protected
// request, so they are swept rather than left to accumulate with uptime.
const sweep = setInterval(() => {
  void Promise.all([pruneExpired(db), pruneExpiredOAuth(db)]).catch((error) => {
    process.stderr.write(`[prune] ${String(error)}\n`);
  });
}, 60 * 60 * 1000);
sweep.unref();

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    clearInterval(sweep);
    server.close(() => {
      void db.close().then(() => process.exit(0));
    });
  });
}
