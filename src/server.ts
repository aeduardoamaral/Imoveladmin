import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { closePool } from './db.js';

const config = loadConfig();
const app = await buildApp();

const shutdown = async () => {
  await app.close();
  await closePool();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.PORT, host: config.HOST });
