import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../audit.js';
import { authenticate, dbContext, forbidImpersonation, requirePrincipal, requireRoles } from '../auth/principal.js';
import { issueInvitation, revokeAdministradoraSessions } from '../auth/service.js';
import { withTx } from '../db.js';
import { notFound } from '../errors.js';
import {
  buildUpdate,
  camel,
  optionalText,
  trimmed,
  zCep,
  zCnpj,
  zCpf,
  zEmail,
  zIdParam,
  zPage,
  zTelefone,
  zUf,
} from '../http.js';

const COLUMNS = `id, razao_social, nome_fantasia, cnpj, email, telefone, cep, logradouro, numero,
  complemento, bairro, cidade, uf, status, created_at, updated_at`;

const dados = z.object({
  razaoSocial: trimmed(200),
  nomeFantasia: optionalText(200),
  cnpj: zCnpj,
  email: zEmail,
  telefone: zTelefone.nullish(),
  cep: zCep.nullish(),
  logradouro: optionalText(200),
  numero: optionalText(20),
  complemento: optionalText(100),
  bairro: optionalText(100),
  cidade: optionalText(100),
  uf: zUf.nullish(),
});

const UPDATE_COLUMNS = {
  razaoSocial: 'razao_social',
  nomeFantasia: 'nome_fantasia',
  cnpj: 'cnpj',
  email: 'email',
  telefone: 'telefone',
  cep: 'cep',
  logradouro: 'logradouro',
  numero: 'numero',
  complemento: 'complemento',
  bairro: 'bairro',
  cidade: 'cidade',
  uf: 'uf',
};

export async function administradoraRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);

  // Cadastro de administradora + gestor responsável (somente Master).
  app.post('/administradoras', { preHandler: [requireRoles('MASTER'), forbidImpersonation] }, async (req, reply) => {
    const p = requirePrincipal(req);
    const body = dados
      .extend({
        gestor: z.object({
          nome: trimmed(150),
          email: zEmail,
          cpf: zCpf.nullish(),
          telefone: zTelefone.nullish(),
        }),
      })
      .parse(req.body);

    const result = await withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `INSERT INTO administradoras (razao_social, nome_fantasia, cnpj, email, telefone, cep, logradouro,
                                      numero, complemento, bairro, cidade, uf, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING ${COLUMNS}`,
        [body.razaoSocial, body.nomeFantasia ?? null, body.cnpj, body.email, body.telefone ?? null, body.cep ?? null,
          body.logradouro ?? null, body.numero ?? null, body.complemento ?? null, body.bairro ?? null,
          body.cidade ?? null, body.uf ?? null, p.userId],
      );
      const adm = rows[0];
      const { rows: urows } = await tx.query(
        `INSERT INTO users (administradora_id, nome, email, cpf, telefone, role, status, created_by)
         VALUES ($1, $2, $3, $4, $5, 'ADMIN_GESTOR', 'PENDENTE', $6)
         RETURNING id, nome, email, role, status`,
        [adm.id, body.gestor.nome, body.gestor.email, body.gestor.cpf ?? null, body.gestor.telefone ?? null, p.userId],
      );
      const gestor = urows[0];
      const convite = await issueInvitation(tx, gestor.id, p.userId);
      await audit(tx, req, { action: 'ADMINISTRADORA_CRIADA', entity: 'administradora', entityId: adm.id, administradoraId: adm.id, details: { cnpj: adm.cnpj, razaoSocial: adm.razao_social } });
      await audit(tx, req, { action: 'USUARIO_CRIADO', entity: 'user', entityId: gestor.id, administradoraId: adm.id, details: { email: gestor.email, papel: gestor.role } });
      return { administradora: camel(adm), gestor: camel(gestor), convite: { url: convite.url, expiraEm: convite.expiraEm } };
    });
    return reply.status(201).send(result);
  });

  app.get('/administradoras', { preHandler: requireRoles('MASTER') }, async (req) => {
    const p = requirePrincipal(req);
    const q = zPage
      .extend({
        status: z.enum(['ATIVA', 'SUSPENSA', 'INATIVA']).optional(),
        busca: z.string().trim().max(100).optional(),
      })
      .parse(req.query);
    return withTx(dbContext(p), async (tx) => {
      const where: string[] = [];
      const params: unknown[] = [];
      if (q.status) {
        params.push(q.status);
        where.push(`status = $${params.length}`);
      }
      if (q.busca) {
        params.push(`%${q.busca.replace(/[\\%_]/g, '\\$&')}%`);
        where.push(`(razao_social ILIKE $${params.length} OR nome_fantasia ILIKE $${params.length} OR cnpj ILIKE $${params.length})`);
      }
      const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const { rows: [{ total }] } = await tx.query(`SELECT count(*)::int AS total FROM administradoras ${w}`, params);
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `SELECT ${COLUMNS} FROM administradoras ${w} ORDER BY razao_social LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { dados: rows.map(camel), total, pagina: q.pagina, porPagina: q.porPagina };
    });
  });

  // Master vê qualquer uma; usuários da administradora veem somente a própria (garantido também pelo RLS).
  app.get('/administradoras/:id', async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(`SELECT ${COLUMNS} FROM administradoras WHERE id = $1`, [id]);
      if (!rows[0]) throw notFound('Administradora não encontrada');
      return camel(rows[0]);
    });
  });

  app.patch('/administradoras/:id', { preHandler: [requireRoles('MASTER'), forbidImpersonation] }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = dados.partial().strict().parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { sets, values } = buildUpdate(body, UPDATE_COLUMNS, 2);
      if (!sets.length) {
        const { rows } = await tx.query(`SELECT ${COLUMNS} FROM administradoras WHERE id = $1`, [id]);
        if (!rows[0]) throw notFound('Administradora não encontrada');
        return camel(rows[0]);
      }
      const { rows } = await tx.query(
        `UPDATE administradoras SET ${sets.join(', ')} WHERE id = $1 RETURNING ${COLUMNS}`,
        [id, ...values],
      );
      if (!rows[0]) throw notFound('Administradora não encontrada');
      await audit(tx, req, { action: 'ADMINISTRADORA_ALTERADA', entity: 'administradora', entityId: id, administradoraId: id, details: { campos: Object.keys(body) } });
      return camel(rows[0]);
    });
  });

  // Suspensão/inativação derruba imediatamente todas as sessões da administradora.
  app.patch('/administradoras/:id/status', { preHandler: [requireRoles('MASTER'), forbidImpersonation] }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({ status: z.enum(['ATIVA', 'SUSPENSA', 'INATIVA']), motivo: z.string().trim().min(5).max(500) })
      .parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `UPDATE administradoras SET status = $2 WHERE id = $1 RETURNING ${COLUMNS}`,
        [id, body.status],
      );
      if (!rows[0]) throw notFound('Administradora não encontrada');
      if (body.status !== 'ATIVA') await revokeAdministradoraSessions(tx, id, `ADMINISTRADORA_${body.status}`);
      await audit(tx, req, { action: 'ADMINISTRADORA_STATUS_ALTERADO', entity: 'administradora', entityId: id, administradoraId: id, details: { status: body.status, motivo: body.motivo } });
      return camel(rows[0]);
    });
  });
}
