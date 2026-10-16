import pg from 'pg';
import { loadConfig } from './config.js';

export type DbRole = 'system' | 'master' | 'tenant';

export interface DbContext {
  role: DbRole;
  tenantId?: string | null;
}

// Colunas DATE voltam como texto AAAA-MM-DD (sem conversão de fuso horário).
// NUMERIC já volta como texto, preservando centavos exatos.
pg.types.setTypeParser(pg.types.builtins.DATE, (v) => v);

let pool: pg.Pool | undefined;

export function getPool(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: loadConfig().DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30_000,
      statement_timeout: 15_000,
    });
  }
  return pool;
}

export async function closePool(): Promise<void> {
  await pool?.end();
  pool = undefined;
}

export type Tx = pg.PoolClient;

/**
 * Executa `fn` em uma transação com o contexto de segurança declarado para o
 * Row-Level Security. O contexto vale somente para esta transação (SET LOCAL),
 * de modo que conexões reaproveitadas do pool nunca herdam contexto anterior.
 */
export async function withTx<T>(ctx: DbContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (ctx.role === 'tenant' && !ctx.tenantId) {
    throw new Error('Contexto tenant exige tenantId');
  }
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT set_config('app.role', $1, true), set_config('app.tenant_id', $2, true),
              set_config('TimeZone', 'America/Sao_Paulo', true)`,
      [ctx.role, ctx.role === 'tenant' ? ctx.tenantId : ''],
    );
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}
