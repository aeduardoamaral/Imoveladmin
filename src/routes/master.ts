import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../audit.js';
import { authenticate, dbContext, forbidImpersonation, requirePrincipal, requireRoles } from '../auth/principal.js';
import { createSession, IMPERSONATION_TTL_MS } from '../auth/service.js';
import { withTx } from '../db.js';
import { badRequest, notFound } from '../errors.js';
import { camel, zPage, zUuid } from '../http.js';
import { signAccessToken } from '../security/jwt.js';

export async function masterRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  app.addHook('preHandler', requireRoles('MASTER'));

  /**
   * Acesso assistido: o Master entra na conta de qualquer usuário de qualquer
   * administradora. Exige motivo, dura no máximo 30 minutos, não pode ser
   * renovado e todas as ações ficam registradas com o Master como responsável.
   */
  app.post('/master/acesso-assistido', { preHandler: forbidImpersonation, config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req) => {
    const p = requirePrincipal(req);
    const body = z.object({ usuarioId: zUuid, motivo: z.string().trim().min(10).max(500) }).parse(req.body);
    const result = await withTx({ role: 'system' }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT u.id, u.role, u.status, u.administradora_id, a.status AS administradora_status
           FROM users u LEFT JOIN administradoras a ON a.id = u.administradora_id WHERE u.id = $1`,
        [body.usuarioId],
      );
      const target = rows[0];
      if (!target) throw notFound('Usuário não encontrado');
      if (target.role === 'MASTER') throw badRequest('Não é permitido acesso assistido a outro Master');
      if (target.status !== 'ATIVO' || target.administradora_status !== 'ATIVA') throw badRequest('Usuário ou administradora inativos');
      const session = await createSession(tx, req, target.id, {
        impersonatorId: p.userId,
        reason: body.motivo,
        expiresAt: new Date(Date.now() + IMPERSONATION_TTL_MS),
      });
      await audit(tx, req, {
        action: 'ACESSO_ASSISTIDO_INICIADO',
        actorUserId: p.userId,
        impersonatorId: null,
        entity: 'user',
        entityId: target.id,
        administradoraId: target.administradora_id,
        details: { motivo: body.motivo, sessao: session.sessionId },
      });
      return { session, userId: target.id as string };
    });
    const ttl = IMPERSONATION_TTL_MS / 1000;
    return {
      accessToken: await signAccessToken({ sub: result.userId, sid: result.session.sessionId }, ttl),
      tokenType: 'Bearer',
      expiraEmSegundos: ttl,
    };
  });

  app.get('/master/auditoria', async (req) => {
    const p = requirePrincipal(req);
    const q = zPage
      .extend({
        administradoraId: zUuid.optional(),
        usuarioId: zUuid.optional(),
        acao: z.string().regex(/^[A-Z_]{2,60}$/).optional(),
        de: z.coerce.date().optional(),
        ate: z.coerce.date().optional(),
      })
      .parse(req.query);
    return withTx(dbContext(p), async (tx) => {
      const where: string[] = [];
      const params: unknown[] = [];
      const add = (sql: string, v: unknown) => {
        params.push(v);
        where.push(sql.replaceAll('?', `$${params.length}`));
      };
      if (q.administradoraId) add('administradora_id = ?', q.administradoraId);
      if (q.usuarioId) add('(actor_user_id = ? OR impersonator_id = ?)', q.usuarioId);
      if (q.acao) add('action = ?', q.acao);
      if (q.de) add('at >= ?', q.de);
      if (q.ate) add('at <= ?', q.ate);
      const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `SELECT id::text, at, actor_user_id, impersonator_id, administradora_id, action, entity, entity_id,
                host(ip) AS ip, user_agent, details, hash
           FROM audit_logs ${w} ORDER BY id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { dados: rows.map(camel), pagina: q.pagina, porPagina: q.porPagina };
    });
  });

  // Verifica a integridade da cadeia de hashes da auditoria.
  app.get('/master/auditoria/integridade', async (req) => {
    const p = requirePrincipal(req);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(`SELECT total::int, broken_at::text FROM audit_verify_chain()`);
      return { integra: rows[0].broken_at === null, totalRegistros: rows[0].total, quebraNoRegistro: rows[0].broken_at };
    });
  });

  app.get('/master/sessoes', async (req) => {
    const p = requirePrincipal(req);
    const q = zPage.extend({ usuarioId: zUuid.optional() }).parse(req.query);
    return withTx(dbContext(p), async (tx) => {
      const params: unknown[] = [];
      let w = 'WHERE s.revoked_at IS NULL AND s.expires_at > now()';
      if (q.usuarioId) {
        params.push(q.usuarioId);
        w += ` AND s.user_id = $1`;
      }
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `SELECT s.id, s.user_id, u.nome, u.email, u.administradora_id, s.impersonator_id, host(s.ip) AS ip,
                s.user_agent, s.created_at, s.expires_at
           FROM sessions s JOIN users u ON u.id = s.user_id ${w}
          ORDER BY s.created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { dados: rows.map(camel), pagina: q.pagina, porPagina: q.porPagina };
    });
  });

  app.post('/master/sessoes/:id/revogar', async (req) => {
    const p = requirePrincipal(req);
    const { id } = z.object({ id: zUuid }).parse(req.params);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `UPDATE sessions SET revoked_at = now(), revoked_reason = 'REVOGADA_PELO_MASTER'
          WHERE family_id = (SELECT family_id FROM sessions WHERE id = $1) AND revoked_at IS NULL
          RETURNING user_id`,
        [id],
      );
      if (!rows.length) throw notFound('Sessão não encontrada ou já encerrada');
      await audit(tx, req, { action: 'SESSAO_REVOGADA', entity: 'session', entityId: id, details: { usuario: rows[0].user_id } });
      return { ok: true };
    });
  });
}
