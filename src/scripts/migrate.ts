import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';

/**
 * Aplica as migrações em ordem, cada uma em sua própria transação,
 * usando o papel DONO do banco (DATABASE_OWNER_URL).
 */
export async function migrate(ownerUrl: string, appRole: string, dir = join(process.cwd(), 'migrations')): Promise<string[]> {
  if (!/^[a-z_][a-z0-9_]*$/.test(appRole)) throw new Error('APP_DB_ROLE inválido');
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  const applied: string[] = [];
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
    const { rows } = await client.query<{ name: string }>(`SELECT name FROM schema_migrations`);
    const done = new Set(rows.map((r) => r.name));
    const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = await readFile(join(dir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(`SELECT set_config('migrate.app_role', $1, true)`, [appRole]);
        await client.query(sql);
        await client.query(`INSERT INTO schema_migrations (name) VALUES ($1)`, [file]);
        await client.query('COMMIT');
        applied.push(file);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`Falha na migração ${file}: ${(err as Error).message}`);
      }
    }
  } finally {
    await client.end();
  }
  return applied;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const url = process.env.DATABASE_OWNER_URL;
  if (!url) throw new Error('Defina DATABASE_OWNER_URL');
  const applied = await migrate(url, process.env.APP_DB_ROLE ?? 'imovel_app');
  console.log(applied.length ? `Migrações aplicadas: ${applied.join(', ')}` : 'Banco já está atualizado.');
}
