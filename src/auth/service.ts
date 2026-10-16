import { randomUUID } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { loadConfig } from '../config.js';
import type { Tx } from '../db.js';
import { randomToken, sha256 } from '../security/crypto.js';

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // vida máxima absoluta da sessão
export const IMPERSONATION_TTL_MS = 30 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const CHALLENGE_MAX_ATTEMPTS = 5;
export const INVITE_TTL_MS = 72 * 60 * 60 * 1000;
export const MAX_FAILED_LOGINS = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;

export interface NewSession {
  sessionId: string;
  familyId: string;
  refreshToken: string | null;
  expiresAt: Date;
}

export async function createSession(
  tx: Tx,
  req: FastifyRequest,
  userId: string,
  opts: { familyId?: string; expiresAt?: Date; impersonatorId?: string; reason?: string } = {},
): Promise<NewSession> {
  const impersonating = Boolean(opts.impersonatorId);
  // Sessões de impersonação não têm refresh token: expiram e acabou.
  const refreshToken = impersonating ? null : randomToken(32);
  const familyId = opts.familyId ?? randomUUID();
  const expiresAt = opts.expiresAt ?? new Date(Date.now() + (impersonating ? IMPERSONATION_TTL_MS : SESSION_TTL_MS));
  const { rows } = await tx.query(
    `INSERT INTO sessions (user_id, family_id, refresh_hash, impersonator_id, impersonation_reason, ip, user_agent, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
    [
      userId,
      familyId,
      refreshToken ? sha256(refreshToken) : null,
      opts.impersonatorId ?? null,
      opts.reason ?? null,
      req.ip,
      req.headers['user-agent']?.slice(0, 300) ?? null,
      expiresAt,
    ],
  );
  return { sessionId: rows[0].id, familyId, refreshToken, expiresAt };
}

/** Revoga todas as sessões do usuário (inclusive impersonações feitas por ele). Valida o tenant no banco. */
export async function revokeUserSessions(tx: Tx, userId: string, reason: string): Promise<void> {
  await tx.query(`SELECT revoke_user_sessions($1, $2)`, [userId, reason]);
}

export async function revokeAdministradoraSessions(tx: Tx, administradoraId: string, reason: string): Promise<void> {
  await tx.query(
    `UPDATE sessions SET revoked_at = now(), revoked_reason = $2
      WHERE revoked_at IS NULL AND user_id IN (SELECT id FROM users WHERE administradora_id = $1)`,
    [administradoraId, reason],
  );
}

export interface Invitation {
  token: string;
  url: string;
  expiraEm: Date;
}

/** Gera convite de uso único. Convites anteriores do usuário são invalidados. */
export async function issueInvitation(tx: Tx, userId: string, createdBy: string | null): Promise<Invitation> {
  const token = randomToken(32);
  const expiraEm = new Date(Date.now() + INVITE_TTL_MS);
  await tx.query(`UPDATE invitations SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`, [userId]);
  await tx.query(
    `INSERT INTO invitations (user_id, token_hash, created_by, expires_at) VALUES ($1, $2, $3, $4)`,
    [userId, sha256(token), createdBy, expiraEm],
  );
  const url = `${loadConfig().APP_PUBLIC_URL.replace(/\/$/, '')}/convite#${token}`;
  return { token, url, expiraEm };
}
