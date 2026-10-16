import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../audit.js';
import { authenticate, dbContext, requirePrincipal, requireRoles } from '../auth/principal.js';
import { withTx } from '../db.js';
import { badRequest, notFound } from '../errors.js';
import { buildUpdate, camel, optionalText, trimmed, zCep, zCnpj, zIdParam, zPage, zUf, zUuid } from '../http.js';
import { resolveAdministradora } from './usuarios.js';

const COLUMNS = `id, administradora_id, nome, cnpj, tipo, num_unidades, num_blocos, cep, logradouro, numero,
  complemento, bairro, cidade, uf, status, created_at, updated_at`;

const dados = z.object({
  nome: trimmed(200),
  cnpj: zCnpj.nullish(),
  tipo: z.enum(['RESIDENCIAL', 'COMERCIAL', 'MISTO']).default('RESIDENCIAL'),
  numUnidades: z.number().int().min(0).max(100000).nullish(),
  numBlocos: z.number().int().min(0).max(1000).nullish(),
  cep: zCep,
  logradouro: trimmed(200),
  numero: trimmed(20),
  complemento: optionalText(100),
  bairro: trimmed(100),
  cidade: trimmed(100),
  uf: zUf,
});

const UPDATE_COLUMNS = {
  nome: 'nome',
  cnpj: 'cnpj',
  tipo: 'tipo',
  numUnidades: 'num_unidades',
  numBlocos: 'num_blocos',
  cep: 'cep',
  logradouro: 'logradouro',
  numero: 'numero',
  complemento: 'complemento',
  bairro: 'bairro',
  cidade: 'cidade',
  uf: 'uf',
};

export async function condominioRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  const gestao = requireRoles('MASTER', 'ADMIN_GESTOR');

  // Todos os papéis da administradora consultam; o RLS restringe à própria administradora.
  app.get('/condominios', async (req) => {
    const p = requirePrincipal(req);
    const q = zPage
      .extend({
        administradoraId: zUuid.optional(),
        status: z.enum(['ATIVO', 'INATIVO']).optional(),
        busca: z.string().trim().max(100).optional(),
      })
      .parse(req.query);
    return withTx(dbContext(p), async (tx) => {
      const where: string[] = [];
      const params: unknown[] = [];
      const admId = p.role === 'MASTER' ? q.administradoraId : resolveAdministradora(p, q.administradoraId);
      if (admId) {
        params.push(admId);
        where.push(`administradora_id = $${params.length}`);
      }
      if (q.status) {
        params.push(q.status);
        where.push(`status = $${params.length}`);
      }
      if (q.busca) {
        params.push(`%${q.busca.replace(/[\\%_]/g, '\\$&')}%`);
        where.push(`(nome ILIKE $${params.length} OR cidade ILIKE $${params.length} OR cnpj ILIKE $${params.length})`);
      }
      const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const { rows: [{ total }] } = await tx.query(`SELECT count(*)::int AS total FROM condominios ${w}`, params);
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `SELECT ${COLUMNS} FROM condominios ${w} ORDER BY nome LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { dados: rows.map(camel), total, pagina: q.pagina, porPagina: q.porPagina };
    });
  });

  app.get('/condominios/:id', async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(`SELECT ${COLUMNS} FROM condominios WHERE id = $1`, [id]);
      if (!rows[0]) throw notFound('Condomínio não encontrado');
      return camel(rows[0]);
    });
  });

  app.post('/condominios', { preHandler: gestao }, async (req, reply) => {
    const p = requirePrincipal(req);
    const body = dados.extend({ administradoraId: zUuid.nullish() }).parse(req.body);
    const administradoraId = resolveAdministradora(p, body.administradoraId);
    const row = await withTx(dbContext(p), async (tx) => {
      const { rows: adm } = await tx.query(`SELECT status FROM administradoras WHERE id = $1`, [administradoraId]);
      if (!adm[0]) throw notFound('Administradora não encontrada');
      if (adm[0].status !== 'ATIVA') throw badRequest('Administradora não está ativa');
      const { rows } = await tx.query(
        `INSERT INTO condominios (administradora_id, nome, cnpj, tipo, num_unidades, num_blocos, cep, logradouro,
                                  numero, complemento, bairro, cidade, uf, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING ${COLUMNS}`,
        [administradoraId, body.nome, body.cnpj ?? null, body.tipo, body.numUnidades ?? null, body.numBlocos ?? null,
          body.cep, body.logradouro, body.numero, body.complemento ?? null, body.bairro, body.cidade, body.uf, p.userId],
      );
      await audit(tx, req, { action: 'CONDOMINIO_CRIADO', entity: 'condominio', entityId: rows[0].id, administradoraId, details: { nome: body.nome, cnpj: body.cnpj ?? null } });
      return rows[0];
    });
    return reply.status(201).send(camel(row));
  });

  app.patch('/condominios/:id', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = dados.partial().strict().parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { sets, values } = buildUpdate(body, UPDATE_COLUMNS, 2);
      const sql = sets.length
        ? `UPDATE condominios SET ${sets.join(', ')} WHERE id = $1 RETURNING ${COLUMNS}`
        : `SELECT ${COLUMNS} FROM condominios WHERE id = $1`;
      const { rows } = await tx.query(sql, [id, ...values]);
      if (!rows[0]) throw notFound('Condomínio não encontrado');
      if (sets.length) {
        await audit(tx, req, { action: 'CONDOMINIO_ALTERADO', entity: 'condominio', entityId: id, administradoraId: rows[0].administradora_id, details: { campos: Object.keys(body) } });
      }
      return camel(rows[0]);
    });
  });

  app.patch('/condominios/:id/status', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z.object({ status: z.enum(['ATIVO', 'INATIVO']), motivo: z.string().trim().min(5).max(500) }).parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(`UPDATE condominios SET status = $2 WHERE id = $1 RETURNING ${COLUMNS}`, [id, body.status]);
      if (!rows[0]) throw notFound('Condomínio não encontrado');
      await audit(tx, req, { action: 'CONDOMINIO_STATUS_ALTERADO', entity: 'condominio', entityId: id, administradoraId: rows[0].administradora_id, details: { status: body.status, motivo: body.motivo } });
      return camel(rows[0]);
    });
  });
}
