import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { audit } from '../audit.js';
import { authenticate, forbidImpersonation, requirePrincipal } from '../auth/principal.js';
import {
  CHALLENGE_MAX_ATTEMPTS,
  CHALLENGE_TTL_MS,
  createSession,
  LOCKOUT_MS,
  MAX_FAILED_LOGINS,
  revokeUserSessions,
} from '../auth/service.js';
import { loadConfig } from '../config.js';
import { withTx, type Tx } from '../db.js';
import { badRequest, forbidden, HttpError, unauthorized } from '../errors.js';
import { zEmail } from '../http.js';
import { decrypt, encrypt, randomToken, sha256 } from '../security/crypto.js';
import { ACCESS_TOKEN_TTL_SECONDS, signAccessToken } from '../security/jwt.js';
import { burnPasswordCheck, hashPassword, PASSWORD_MAX, passwordProblems, verifyPassword } from '../security/password.js';
import { generateSecret, otpauthUrl, verifyTotp } from '../security/totp.js';

const GENERIC_LOGIN_ERROR = 'Credenciais inválidas ou conta temporariamente bloqueada';
const CSRF_HEADER = 'x-csrf-protection';

export function refreshCookieName(): string {
  return loadConfig().isProd ? '__Secure-rt' : 'rt';
}

function setRefreshCookie(reply: FastifyReply, token: string, expiresAt: Date): void {
  reply.setCookie(refreshCookieName(), token, {
    httpOnly: true,
    secure: loadConfig().isProd,
    sameSite: 'strict',
    path: '/auth',
    expires: expiresAt,
  });
}

function clearRefreshCookie(reply: FastifyReply): void {
  reply.clearCookie(refreshCookieName(), { path: '/auth' });
}

/** Exige cabeçalho customizado: força preflight CORS e bloqueia CSRF por formulário. */
function requireCsrfHeader(req: FastifyRequest): void {
  if (req.headers[CSRF_HEADER] !== '1') throw forbidden('Cabeçalho de proteção CSRF ausente');
}

const strictRateLimit = { rateLimit: { max: 10, timeWindow: '1 minute' } };

export async function authRoutes(app: FastifyInstance): Promise<void> {
  // -------------------------------------------------------------------
  // Etapa 1: e-mail + senha  ->  desafio de MFA (obrigatório para todos)
  // -------------------------------------------------------------------
  app.post('/auth/login', { config: strictRateLimit }, async (req) => {
    const body = z
      .object({ email: zEmail, senha: z.string().min(1).max(PASSWORD_MAX) })
      .parse(req.body);

    const outcome = await withTx({ role: 'system' }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT u.id, u.status, u.password_hash, u.mfa_enabled, u.failed_logins, u.locked_until,
                u.administradora_id, a.status AS administradora_status
           FROM users u LEFT JOIN administradoras a ON a.id = u.administradora_id
          WHERE u.email = $1 FOR UPDATE OF u`,
        [body.email],
      );
      const user = rows[0];

      if (!user || !user.password_hash) {
        await burnPasswordCheck(body.senha);
        await audit(tx, req, { action: 'LOGIN_FALHOU', actorUserId: user?.id ?? null, details: { email: body.email, motivo: 'usuario_inexistente_ou_sem_senha' } });
        return { ok: false as const };
      }

      const locked = user.locked_until && new Date(user.locked_until) > new Date();
      const passwordOk = await verifyPassword(user.password_hash, body.senha);

      if (locked || !passwordOk || user.status !== 'ATIVO') {
        if (!locked && !passwordOk) {
          const failures = user.failed_logins + 1;
          const lockNow = failures >= MAX_FAILED_LOGINS;
          await tx.query(
            `UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1`,
            [user.id, lockNow ? 0 : failures, lockNow ? new Date(Date.now() + LOCKOUT_MS) : user.locked_until],
          );
          if (lockNow) {
            await audit(tx, req, { action: 'CONTA_BLOQUEADA', actorUserId: user.id, administradoraId: user.administradora_id, details: { minutos: LOCKOUT_MS / 60000 } });
          }
        }
        await audit(tx, req, {
          action: 'LOGIN_FALHOU',
          actorUserId: user.id,
          administradoraId: user.administradora_id,
          details: { motivo: locked ? 'conta_bloqueada' : !passwordOk ? 'senha_incorreta' : `status_${user.status}` },
        });
        return { ok: false as const };
      }

      if (user.administradora_id && user.administradora_status !== 'ATIVA') {
        await audit(tx, req, { action: 'LOGIN_FALHOU', actorUserId: user.id, administradoraId: user.administradora_id, details: { motivo: 'administradora_inativa' } });
        return { ok: false as const, blocked: true as const };
      }

      await tx.query(`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, [user.id]);
      const challenge = randomToken(32);
      await tx.query(
        `INSERT INTO auth_challenges (user_id, token_hash, ip, expires_at) VALUES ($1, $2, $3, $4)`,
        [user.id, sha256(challenge), req.ip, new Date(Date.now() + CHALLENGE_TTL_MS)],
      );
      return { ok: true as const, challenge, mfaEnabled: user.mfa_enabled as boolean };
    });

    if (!outcome.ok) {
      if ('blocked' in outcome) throw forbidden('Acesso da administradora suspenso. Contate o suporte.');
      throw new HttpError(401, 'CREDENCIAIS_INVALIDAS', GENERIC_LOGIN_ERROR);
    }
    return {
      etapa: outcome.mfaEnabled ? 'MFA' : 'MFA_CADASTRO',
      desafio: outcome.challenge,
      expiraEmSegundos: CHALLENGE_TTL_MS / 1000,
    };
  });

  // -------------------------------------------------------------------
  // Cadastro do autenticador (primeiro acesso)
  // -------------------------------------------------------------------
  app.post('/auth/mfa/cadastro', { config: strictRateLimit }, async (req) => {
    const body = z.object({ desafio: z.string().min(20).max(100) }).parse(req.body);
    return withTx({ role: 'system' }, async (tx) => {
      const ch = await loadChallenge(tx, body.desafio);
      if (ch.mfa_enabled) throw badRequest('Autenticador já cadastrado');
      const secret = generateSecret();
      await tx.query(`UPDATE auth_challenges SET pending_secret_enc = $2 WHERE id = $1`, [
        ch.id,
        encrypt(secret, `challenge:${ch.id}`),
      ]);
      return { segredo: secret, otpauthUrl: otpauthUrl(secret, ch.email) };
    });
  });

  // -------------------------------------------------------------------
  // Etapa 2: código TOTP  ->  sessão
  // -------------------------------------------------------------------
  app.post('/auth/mfa/verificar', { config: strictRateLimit }, async (req, reply) => {
    const body = z
      .object({ desafio: z.string().min(20).max(100), codigo: z.string().trim().regex(/^\d{6}$/, 'Código inválido') })
      .parse(req.body);

    const result = await withTx({ role: 'system' }, async (tx) => {
      const ch = await loadChallenge(tx, body.desafio);
      await tx.query(`UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = $1`, [ch.id]);

      let secret: string;
      const enrolling = !ch.mfa_enabled;
      if (enrolling) {
        if (!ch.pending_secret_enc) throw badRequest('Cadastre o autenticador antes de verificar');
        secret = decrypt(ch.pending_secret_enc, `challenge:${ch.id}`);
      } else {
        secret = decrypt(ch.mfa_secret_enc, `user:${ch.user_id}`);
      }

      const step = verifyTotp(secret, body.codigo, enrolling ? null : ch.mfa_last_step === null ? null : Number(ch.mfa_last_step));
      if (step === null) {
        await audit(tx, req, { action: 'MFA_FALHOU', actorUserId: ch.user_id, administradoraId: ch.administradora_id });
        return { ok: false as const };
      }

      await tx.query(`UPDATE auth_challenges SET consumed_at = now() WHERE id = $1`, [ch.id]);
      if (enrolling) {
        await tx.query(
          `UPDATE users SET mfa_secret_enc = $2, mfa_enabled = true WHERE id = $1`,
          [ch.user_id, encrypt(secret, `user:${ch.user_id}`)],
        );
        await audit(tx, req, { action: 'MFA_CADASTRADO', actorUserId: ch.user_id, administradoraId: ch.administradora_id });
      }
      await tx.query(`UPDATE users SET mfa_last_step = $2, last_login_at = now() WHERE id = $1`, [ch.user_id, step]);

      const session = await createSession(tx, req, ch.user_id);
      await audit(tx, req, { action: 'LOGIN_SUCESSO', actorUserId: ch.user_id, administradoraId: ch.administradora_id, entity: 'session', entityId: session.sessionId });
      return { ok: true as const, session, userId: ch.user_id as string };
    });

    if (!result.ok) throw new HttpError(401, 'CODIGO_INVALIDO', 'Código inválido');
    setRefreshCookie(reply, result.session.refreshToken!, result.session.expiresAt);
    return {
      accessToken: await signAccessToken({ sub: result.userId, sid: result.session.sessionId }),
      tokenType: 'Bearer',
      expiraEmSegundos: ACCESS_TOKEN_TTL_SECONDS,
    };
  });

  // -------------------------------------------------------------------
  // Renovação com rotação de refresh token e detecção de reuso
  // -------------------------------------------------------------------
  app.post('/auth/refresh', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    requireCsrfHeader(req);
    const token = req.cookies[refreshCookieName()];
    if (!token) throw unauthorized();

    const result = await withTx({ role: 'system' }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT s.id, s.user_id, s.family_id, s.expires_at, s.revoked_at, s.revoked_reason,
                u.status, u.administradora_id, a.status AS administradora_status
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           LEFT JOIN administradoras a ON a.id = u.administradora_id
          WHERE s.refresh_hash = $1 FOR UPDATE OF s`,
        [sha256(token)],
      );
      const s = rows[0];
      if (!s) return { ok: false as const };

      if (s.revoked_at) {
        if (s.revoked_reason === 'ROTACIONADO') {
          // Token antigo reapresentado: possível roubo. Derruba a família inteira.
          await tx.query(
            `UPDATE sessions SET revoked_at = now(), revoked_reason = 'REUSO_DETECTADO'
              WHERE family_id = $1 AND revoked_at IS NULL`,
            [s.family_id],
          );
          await audit(tx, req, { action: 'SEGURANCA_REUSO_REFRESH_TOKEN', actorUserId: s.user_id, administradoraId: s.administradora_id, details: { familia: s.family_id } });
        }
        return { ok: false as const };
      }
      if (new Date(s.expires_at) <= new Date()) return { ok: false as const };
      if (s.status !== 'ATIVO' || (s.administradora_id && s.administradora_status !== 'ATIVA')) {
        await tx.query(`UPDATE sessions SET revoked_at = now(), revoked_reason = 'USUARIO_INATIVO' WHERE id = $1`, [s.id]);
        return { ok: false as const };
      }

      await tx.query(`UPDATE sessions SET revoked_at = now(), revoked_reason = 'ROTACIONADO' WHERE id = $1`, [s.id]);
      const next = await createSession(tx, req, s.user_id, { familyId: s.family_id, expiresAt: new Date(s.expires_at) });
      return { ok: true as const, session: next, userId: s.user_id as string };
    });

    if (!result.ok) {
      clearRefreshCookie(reply);
      throw unauthorized('Sessão expirada. Faça login novamente.');
    }
    setRefreshCookie(reply, result.session.refreshToken!, result.session.expiresAt);
    return {
      accessToken: await signAccessToken({ sub: result.userId, sid: result.session.sessionId }),
      tokenType: 'Bearer',
      expiraEmSegundos: ACCESS_TOKEN_TTL_SECONDS,
    };
  });

  app.post('/auth/logout', { preHandler: authenticate }, async (req, reply) => {
    const p = requirePrincipal(req);
    await withTx({ role: 'system' }, async (tx) => {
      await tx.query(
        `UPDATE sessions SET revoked_at = now(), revoked_reason = 'LOGOUT'
          WHERE family_id = (SELECT family_id FROM sessions WHERE id = $1) AND revoked_at IS NULL`,
        [p.sessionId],
      );
      await audit(tx, req, { action: p.impersonatorId ? 'IMPERSONACAO_ENCERRADA' : 'LOGOUT', administradoraId: p.administradoraId });
    });
    if (!p.impersonatorId) clearRefreshCookie(reply);
    return reply.status(204).send();
  });

  app.get('/auth/me', { preHandler: authenticate }, async (req) => {
    const p = requirePrincipal(req);
    const adm = p.administradoraId
      ? await withTx({ role: 'tenant', tenantId: p.administradoraId }, async (tx) =>
          (await tx.query(`SELECT razao_social, opera_condominios, opera_locacao FROM administradoras WHERE id = $1`, [p.administradoraId])).rows[0])
      : null;
    return {
      administradora: adm
        ? { id: p.administradoraId, razaoSocial: adm.razao_social, operaCondominios: adm.opera_condominios, operaLocacao: adm.opera_locacao }
        : null,
      id: p.userId,
      nome: p.nome,
      email: p.email,
      papel: p.role,
      administradoraId: p.administradoraId,
      acessoAssistidoPor: p.impersonatorId,
    };
  });

  app.post('/auth/senha/alterar', { preHandler: [authenticate, forbidImpersonation], config: strictRateLimit }, async (req) => {
    const p = requirePrincipal(req);
    const body = z
      .object({ senhaAtual: z.string().min(1).max(PASSWORD_MAX), novaSenha: z.string().max(PASSWORD_MAX) })
      .parse(req.body);
    const problems = passwordProblems(body.novaSenha, { email: p.email, nome: p.nome });
    if (problems.length) throw badRequest('Senha fraca', problems);

    const changed = await withTx({ role: 'system' }, async (tx) => {
      const { rows } = await tx.query(`SELECT password_hash FROM users WHERE id = $1 FOR UPDATE`, [p.userId]);
      if (!rows[0] || !(await verifyPassword(rows[0].password_hash, body.senhaAtual))) {
        await audit(tx, req, { action: 'SENHA_ALTERACAO_FALHOU', administradoraId: p.administradoraId });
        return false;
      }
      if (await verifyPassword(rows[0].password_hash, body.novaSenha)) throw badRequest('A nova senha deve ser diferente da atual');
      await tx.query(`UPDATE users SET password_hash = $2, password_changed_at = now() WHERE id = $1`, [
        p.userId,
        await hashPassword(body.novaSenha),
      ]);
      // Encerra todas as outras sessões do usuário.
      await tx.query(
        `UPDATE sessions SET revoked_at = now(), revoked_reason = 'SENHA_ALTERADA'
          WHERE user_id = $1 AND revoked_at IS NULL
            AND family_id <> (SELECT family_id FROM sessions WHERE id = $2)`,
        [p.userId, p.sessionId],
      );
      await audit(tx, req, { action: 'SENHA_ALTERADA', administradoraId: p.administradoraId });
      return true;
    });
    if (!changed) throw new HttpError(401, 'CREDENCIAIS_INVALIDAS', 'Senha atual incorreta');
    return { ok: true };
  });

  // -------------------------------------------------------------------
  // Aceite de convite: define a senha (primeiro acesso ou redefinição)
  // -------------------------------------------------------------------
  app.post('/auth/convite/aceitar', { config: strictRateLimit }, async (req) => {
    const body = z.object({ token: z.string().min(20).max(100), senha: z.string().max(PASSWORD_MAX) }).parse(req.body);

    await withTx({ role: 'system' }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT i.id, i.user_id, u.email, u.nome, u.status, u.administradora_id
           FROM invitations i JOIN users u ON u.id = i.user_id
          WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > now()
          FOR UPDATE OF i`,
        [sha256(body.token)],
      );
      const inv = rows[0];
      if (!inv || inv.status === 'SUSPENSO') throw new HttpError(400, 'CONVITE_INVALIDO', 'Convite inválido ou expirado');

      const problems = passwordProblems(body.senha, { email: inv.email, nome: inv.nome });
      if (problems.length) throw badRequest('Senha fraca', problems);

      await tx.query(`UPDATE invitations SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`, [inv.user_id]);
      await tx.query(
        `UPDATE users SET password_hash = $2, password_changed_at = now(), status = 'ATIVO',
                          failed_logins = 0, locked_until = NULL
          WHERE id = $1`,
        [inv.user_id, await hashPassword(body.senha)],
      );
      await revokeUserSessions(tx, inv.user_id, 'SENHA_DEFINIDA_POR_CONVITE');
      await audit(tx, req, { action: 'CONVITE_ACEITO', actorUserId: inv.user_id, administradoraId: inv.administradora_id, entity: 'user', entityId: inv.user_id });
    });
    return { ok: true };
  });
}

async function loadChallenge(tx: Tx, token: string) {
  const { rows } = await tx.query(
    `SELECT c.id, c.user_id, c.attempts, c.pending_secret_enc,
            u.email, u.status, u.mfa_enabled, u.mfa_secret_enc, u.mfa_last_step, u.administradora_id
       FROM auth_challenges c JOIN users u ON u.id = c.user_id
      WHERE c.token_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now()
      FOR UPDATE OF c, u`,
    [sha256(token)],
  );
  const ch = rows[0];
  if (!ch || ch.status !== 'ATIVO' || ch.attempts >= CHALLENGE_MAX_ATTEMPTS) {
    throw new HttpError(401, 'DESAFIO_INVALIDO', 'Sessão de login expirada. Faça login novamente.');
  }
  return ch;
}
