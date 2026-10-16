import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../audit.js';
import { authenticate, dbContext, forbidImpersonation, requirePrincipal, requireRoles, type Principal } from '../auth/principal.js';
import { issueInvitation, revokeUserSessions } from '../auth/service.js';
import { withTx, type Tx } from '../db.js';
import { badRequest, forbidden, notFound } from '../errors.js';
import { buildUpdate, camel, trimmed, zCpf, zEmail, zIdParam, zPage, zTelefone, zUuid } from '../http.js';

const COLUMNS = `id, administradora_id, nome, email, cpf, telefone, role AS papel, status, mfa_enabled,
  last_login_at, created_at, updated_at`;

const zPapel = z.enum(['MASTER', 'ADMIN_GESTOR', 'ADMIN_COLABORADOR']);

/** Resolve a administradora alvo: Master escolhe; demais usam a própria. */
export function resolveAdministradora(p: Principal, requested: string | null | undefined): string {
  if (p.role === 'MASTER') {
    if (!requested) throw badRequest('Informe administradoraId');
    return requested;
  }
  if (requested && requested !== p.administradoraId) throw forbidden();
  return p.administradoraId!;
}

async function loadUser(tx: Tx, id: string) {
  const { rows } = await tx.query(`SELECT ${COLUMNS}, password_hash IS NOT NULL AS tem_senha FROM users WHERE id = $1 FOR UPDATE`, [id]);
  if (!rows[0]) throw notFound('Usuário não encontrado');
  return rows[0];
}

function publicUser(row: Record<string, unknown>) {
  const { tem_senha: _ignored, ...rest } = row;
  return camel(rest);
}

export async function usuarioRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  const gestao = requireRoles('MASTER', 'ADMIN_GESTOR');

  app.get('/usuarios', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const q = zPage
      .extend({
        administradoraId: zUuid.optional(),
        papel: zPapel.optional(),
        status: z.enum(['PENDENTE', 'ATIVO', 'SUSPENSO']).optional(),
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
      if (q.papel) {
        params.push(q.papel);
        where.push(`role = $${params.length}`);
      }
      if (q.status) {
        params.push(q.status);
        where.push(`status = $${params.length}`);
      }
      const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const { rows: [{ total }] } = await tx.query(`SELECT count(*)::int AS total FROM users ${w}`, params);
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `SELECT ${COLUMNS} FROM users ${w} ORDER BY nome LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { dados: rows.map(camel), total, pagina: q.pagina, porPagina: q.porPagina };
    });
  });

  app.get('/usuarios/:id', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    return withTx(dbContext(p), async (tx) => publicUser(await loadUser(tx, id)));
  });

  app.post('/usuarios', { preHandler: gestao }, async (req, reply) => {
    const p = requirePrincipal(req);
    const body = z
      .object({
        nome: trimmed(150),
        email: zEmail,
        cpf: zCpf.nullish(),
        telefone: zTelefone.nullish(),
        papel: zPapel,
        administradoraId: zUuid.nullish(),
      })
      .parse(req.body);

    let administradoraId: string | null;
    if (body.papel === 'MASTER') {
      // Somente o Master (fora de acesso assistido) cria outro Master.
      if (p.role !== 'MASTER' || p.impersonatorId) throw forbidden();
      if (body.administradoraId) throw badRequest('Usuário Master não pertence a administradora');
      administradoraId = null;
    } else {
      administradoraId = resolveAdministradora(p, body.administradoraId);
    }

    const result = await withTx(dbContext(p), async (tx) => {
      if (administradoraId) {
        const { rows } = await tx.query(`SELECT status FROM administradoras WHERE id = $1`, [administradoraId]);
        if (!rows[0]) throw notFound('Administradora não encontrada');
        if (rows[0].status !== 'ATIVA') throw badRequest('Administradora não está ativa');
      }
      const { rows } = await tx.query(
        `INSERT INTO users (administradora_id, nome, email, cpf, telefone, role, status, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'PENDENTE', $7) RETURNING ${COLUMNS}`,
        [administradoraId, body.nome, body.email, body.cpf ?? null, body.telefone ?? null, body.papel, p.userId],
      );
      const user = rows[0];
      const convite = await issueInvitation(tx, user.id, p.userId);
      await audit(tx, req, { action: 'USUARIO_CRIADO', entity: 'user', entityId: user.id, administradoraId, details: { email: user.email, papel: user.papel } });
      return { usuario: camel(user), convite: { url: convite.url, expiraEm: convite.expiraEm } };
    });
    return reply.status(201).send(result);
  });

  app.patch('/usuarios/:id', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({
        nome: trimmed(150).optional(),
        telefone: zTelefone.nullish(),
        papel: z.enum(['ADMIN_GESTOR', 'ADMIN_COLABORADOR']).optional(),
      })
      .strict()
      .parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const current = await loadUser(tx, id);
      if (body.papel && id === p.userId) throw forbidden('Você não pode alterar o próprio papel');
      if (body.papel && current.papel === 'MASTER') throw forbidden('Papel do Master não pode ser alterado');
      const { sets, values } = buildUpdate(body, { nome: 'nome', telefone: 'telefone', papel: 'role' }, 2);
      if (!sets.length) return publicUser(current);
      const { rows } = await tx.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1 RETURNING ${COLUMNS}`, [id, ...values]);
      if (body.papel && body.papel !== current.papel) await revokeUserSessions(tx, id, 'PAPEL_ALTERADO');
      await audit(tx, req, { action: 'USUARIO_ALTERADO', entity: 'user', entityId: id, administradoraId: current.administradora_id, details: { campos: Object.keys(body), papelAnterior: current.papel, papelNovo: body.papel } });
      return camel(rows[0]);
    });
  });

  app.patch('/usuarios/:id/status', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({ status: z.enum(['ATIVO', 'SUSPENSO']), motivo: z.string().trim().min(5).max(500) })
      .parse(req.body);
    if (id === p.userId || (p.impersonatorId && id === p.impersonatorId)) throw forbidden('Você não pode alterar o próprio status');
    return withTx(dbContext(p), async (tx) => {
      const current = await loadUser(tx, id);
      if (body.status === 'ATIVO' && !current.tem_senha) throw badRequest('Usuário ainda não aceitou o convite');
      const { rows } = await tx.query(`UPDATE users SET status = $2 WHERE id = $1 RETURNING ${COLUMNS}`, [id, body.status]);
      if (body.status === 'SUSPENSO') await revokeUserSessions(tx, id, 'USUARIO_SUSPENSO');
      await audit(tx, req, { action: 'USUARIO_STATUS_ALTERADO', entity: 'user', entityId: id, administradoraId: current.administradora_id, details: { status: body.status, motivo: body.motivo } });
      return camel(rows[0]);
    });
  });

  // Reenvia convite (primeiro acesso) ou gera link de redefinição de senha.
  app.post('/usuarios/:id/convite', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    if (id === p.userId) throw forbidden('Use a alteração de senha para a sua própria conta');
    return withTx(dbContext(p), async (tx) => {
      const current = await loadUser(tx, id);
      if (current.status === 'SUSPENSO') throw badRequest('Usuário suspenso');
      const convite = await issueInvitation(tx, id, p.userId);
      await audit(tx, req, { action: 'CONVITE_EMITIDO', entity: 'user', entityId: id, administradoraId: current.administradora_id });
      return { convite: { url: convite.url, expiraEm: convite.expiraEm } };
    });
  });

  // Reset do autenticador (perda do celular). Usuário cadastra novo MFA no próximo login.
  app.post('/usuarios/:id/mfa/resetar', { preHandler: [gestao, forbidImpersonation] }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z.object({ motivo: z.string().trim().min(5).max(500) }).parse(req.body);
    if (id === p.userId) throw forbidden('Você não pode resetar o próprio MFA');
    return withTx(dbContext(p), async (tx) => {
      const current = await loadUser(tx, id);
      await tx.query(
        `UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_last_step = NULL WHERE id = $1`,
        [id],
      );
      await revokeUserSessions(tx, id, 'MFA_RESETADO');
      await audit(tx, req, { action: 'MFA_RESETADO', entity: 'user', entityId: id, administradoraId: current.administradora_id, details: { motivo: body.motivo } });
      return { ok: true };
    });
  });
}
