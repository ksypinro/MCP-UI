import { createDb } from './db/index.ts';
import { createApp } from './http/app.ts';
import { DATABASE_PATH, PORT } from './config.ts';

const db = await createDb(DATABASE_PATH);
const app = createApp(db);

const server = app.listen(PORT, () => {
  process.stdout.write(`iot-switch-server listening on :${PORT}\n  database ${DATABASE_PATH}\n`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    server.close(() => {
      void db.close().then(() => process.exit(0));
    });
  });
}
