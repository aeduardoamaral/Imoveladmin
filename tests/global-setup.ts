import pg from 'pg';
import { migrate } from '../src/scripts/migrate.js';

export default async function setup(): Promise<void> {
  const ownerUrl = process.env.TEST_DATABASE_OWNER_URL ?? 'postgres://imovel_owner:owner_dev_pw@localhost:5432/imoveladmin_test';
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  await client.query('DROP SCHEMA IF EXISTS public CASCADE');
  await client.query('CREATE SCHEMA public');
  await client.end();
  await migrate(ownerUrl, 'imovel_app');
}
