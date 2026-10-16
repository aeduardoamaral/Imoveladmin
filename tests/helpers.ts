import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import { buildApp } from '../src/app.js';
import { withTx } from '../src/db.js';
import { encrypt } from '../src/security/crypto.js';
import { hashPassword } from '../src/security/password.js';
import { codeAt, currentStep, generateSecret } from '../src/security/totp.js';

export const PASSWORD = 'Cofre#Forte-2026!';

let app: FastifyInstance | undefined;
export async function getApp(): Promise<FastifyInstance> {
  app ??= await buildApp({ logger: false });
  return app;
}

/** Conexão como DONO do banco (apenas para preparar/inspecionar cenários nos testes). */
export async function ownerQuery(sql: string, params: unknown[] = []) {
  const c = new pg.Client({ connectionString: process.env.DATABASE_OWNER_URL });
  await c.connect();
  try {
    return await c.query(sql, params);
  } finally {
    await c.end();
  }
}

let ipCounter = 1;
/** IP distinto por chamada, para que os limites de taxa não interfiram entre testes. */
export function nextIp(): string {
  ipCounter++;
  return `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;
}

export interface TestUser {
  id: string;
  email: string;
  secret: string;
  administradoraId: string | null;
}

export async function createActiveUser(opts: {
  role: 'MASTER' | 'ADMIN_GESTOR' | 'ADMIN_COLABORADOR';
  administradoraId?: string | null;
  nome?: string;
}): Promise<TestUser> {
  const email = `u-${randomUUID().slice(0, 8)}@teste.com.br`;
  const secret = generateSecret();
  const hash = await hashPassword(PASSWORD);
  const id = await withTx({ role: 'system' }, async (tx) => {
    const { rows } = await tx.query(
      `INSERT INTO users (administradora_id, nome, email, role, status, password_hash, mfa_enabled)
       VALUES ($1, $2, $3, $4, 'ATIVO', $5, true) RETURNING id`,
      [opts.administradoraId ?? null, opts.nome ?? 'Usuário Teste', email, opts.role, hash],
    );
    await tx.query(`UPDATE users SET mfa_secret_enc = $2 WHERE id = $1`, [rows[0].id, encrypt(secret, `user:${rows[0].id}`)]);
    return rows[0].id as string;
  });
  return { id, email, secret, administradoraId: opts.administradoraId ?? null };
}

export async function createAdministradora(nome = 'Adm Teste'): Promise<string> {
  return withTx({ role: 'system' }, async (tx) => {
    const cnpj = randomCnpj();
    const { rows } = await tx.query(
      `INSERT INTO administradoras (razao_social, cnpj, email) VALUES ($1, $2, 'contato@adm.com.br') RETURNING id`,
      [nome, cnpj],
    );
    return rows[0].id as string;
  });
}

export function randomCnpj(): string {
  const base = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10));
  const dv = (nums: number[], weights: number[]) => {
    const r = nums.reduce((a, n, i) => a + n * weights[i]!, 0) % 11;
    return r < 2 ? 0 : 11 - r;
  };
  const d1 = dv(base, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = dv([...base, d1], [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return [...base, d1, d2].join('');
}

/** Login completo (senha + TOTP). Retorna access token e cookie de refresh. */
export async function login(user: TestUser, ip = nextIp()): Promise<{ token: string; cookie: string }> {
  const a = await getApp();
  await ownerQuery(`UPDATE users SET mfa_last_step = NULL WHERE id = $1`, [user.id]);
  const r1 = await a.inject({ method: 'POST', url: '/auth/login', remoteAddress: ip, payload: { email: user.email, senha: PASSWORD } });
  if (r1.statusCode !== 200) throw new Error(`login falhou: ${r1.statusCode} ${r1.body}`);
  const r2 = await a.inject({
    method: 'POST',
    url: '/auth/mfa/verificar',
    remoteAddress: ip,
    payload: { desafio: r1.json().desafio, codigo: codeAt(user.secret, currentStep()) },
  });
  if (r2.statusCode !== 200) throw new Error(`mfa falhou: ${r2.statusCode} ${r2.body}`);
  const setCookie = r2.headers['set-cookie'];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)!.split(';')[0]!;
  return { token: r2.json().accessToken, cookie };
}

export function auth(token: string) {
  return { authorization: `Bearer ${token}` };
}
