import type { FastifyRequest } from 'fastify';
import type { Tx } from './db.js';

export interface AuditEntry {
  action: string;
  entity?: string;
  entityId?: string | null;
  administradoraId?: string | null;
  details?: Record<string, unknown>;
  actorUserId?: string | null;
  impersonatorId?: string | null;
}

/**
 * Registra evento na trilha de auditoria encadeada. Deve ser chamado dentro da
 * mesma transação da operação auditada: se a operação falhar, o registro também
 * é desfeito; se o registro falhar, a operação é desfeita.
 */
export async function audit(tx: Tx, req: FastifyRequest | null, entry: AuditEntry): Promise<void> {
  const p = req?.principal;
  await tx.query(
    `INSERT INTO audit_logs (actor_user_id, impersonator_id, administradora_id, action, entity, entity_id, ip, user_agent, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      entry.actorUserId !== undefined ? entry.actorUserId : (p?.userId ?? null),
      entry.impersonatorId !== undefined ? entry.impersonatorId : (p?.impersonatorId ?? null),
      entry.administradoraId ?? null,
      entry.action,
      entry.entity ?? null,
      entry.entityId ?? null,
      req?.ip ?? null,
      req?.headers['user-agent']?.slice(0, 300) ?? null,
      JSON.stringify(entry.details ?? {}),
    ],
  );
}
