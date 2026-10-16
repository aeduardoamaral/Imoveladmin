import type { FastifyReply, FastifyRequest } from 'fastify';
import { withTx, type DbContext } from '../db.js';
import { forbidden, unauthorized } from '../errors.js';
import { verifyAccessToken } from '../security/jwt.js';

export type Role = 'MASTER' | 'ADMIN_GESTOR' | 'ADMIN_COLABORADOR';

export interface Principal {
  userId: string;
  sessionId: string;
  role: Role;
  administradoraId: string | null;
  nome: string;
  email: string;
  impersonatorId: string | null;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal?: Principal;
  }
}

export function dbContext(p: Principal): DbContext {
  return p.role === 'MASTER' ? { role: 'master' } : { role: 'tenant', tenantId: p.administradoraId };
}

export function requirePrincipal(req: FastifyRequest): Principal {
  if (!req.principal) throw unauthorized();
  return req.principal;
}

/**
 * Autentica a requisição. Além de validar o JWT, confere no banco a cada
 * requisição se a sessão continua válida, se o usuário continua ATIVO e se a
 * administradora continua ATIVA - revogações têm efeito imediato.
 */
export async function authenticate(req: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw unauthorized();
  const claims = await verifyAccessToken(header.slice(7).trim());
  if (!claims) throw unauthorized('Token inválido ou expirado');

  const row = await withTx({ role: 'system' }, async (tx) => {
    const { rows } = await tx.query(
      `SELECT u.id, u.nome, u.email, u.role, u.administradora_id, s.impersonator_id
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         LEFT JOIN administradoras a ON a.id = u.administradora_id
         LEFT JOIN users imp ON imp.id = s.impersonator_id
        WHERE s.id = $1 AND s.user_id = $2
          AND s.revoked_at IS NULL AND s.expires_at > now()
          AND u.status = 'ATIVO'
          AND (u.administradora_id IS NULL OR a.status = 'ATIVA')
          AND (s.impersonator_id IS NULL OR (imp.status = 'ATIVO' AND imp.role = 'MASTER'))`,
      [claims.sid, claims.sub],
    );
    return rows[0];
  });
  if (!row) throw unauthorized('Sessão inválida ou encerrada');

  req.principal = {
    userId: row.id,
    sessionId: claims.sid,
    role: row.role,
    administradoraId: row.administradora_id,
    nome: row.nome,
    email: row.email,
    impersonatorId: row.impersonator_id,
  };
}

export function requireRoles(...roles: Role[]) {
  return async (req: FastifyRequest): Promise<void> => {
    const p = requirePrincipal(req);
    if (!roles.includes(p.role)) throw forbidden();
  };
}

/** Bloqueia operações sensíveis durante uma sessão de acesso assistido (impersonação). */
export async function forbidImpersonation(req: FastifyRequest): Promise<void> {
  if (requirePrincipal(req).impersonatorId) {
    throw forbidden('Operação não permitida durante acesso assistido');
  }
}
