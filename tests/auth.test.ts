import { describe, expect, it } from 'vitest';
import { codeAt, currentStep } from '../src/security/totp.js';
import { auth, createActiveUser, createAdministradora, getApp, login, nextIp, ownerQuery, PASSWORD } from './helpers.js';

describe('autenticação', () => {
  it('primeiro acesso: convite -> senha -> cadastro obrigatório de MFA -> sessão', async () => {
    const app = await getApp();
    const master = await createActiveUser({ role: 'MASTER' });
    const { token } = await login(master);
    const created = await app.inject({
      method: 'POST', url: '/usuarios', headers: auth(token),
      payload: { nome: 'Outro Master', email: 'outro.master@teste.com.br', papel: 'MASTER' },
    });
    expect(created.statusCode).toBe(201);
    const inviteToken = created.json().convite.url.split('#')[1];

    const weak = await app.inject({ method: 'POST', url: '/auth/convite/aceitar', payload: { token: inviteToken, senha: 'fraca' } });
    expect(weak.statusCode).toBe(400);
    const ok = await app.inject({ method: 'POST', url: '/auth/convite/aceitar', payload: { token: inviteToken, senha: PASSWORD } });
    expect(ok.statusCode).toBe(200);
    const reuse = await app.inject({ method: 'POST', url: '/auth/convite/aceitar', payload: { token: inviteToken, senha: PASSWORD } });
    expect(reuse.statusCode).toBe(400);

    const ip = nextIp();
    const l = await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: ip, payload: { email: 'outro.master@teste.com.br', senha: PASSWORD } });
    expect(l.json().etapa).toBe('MFA_CADASTRO');
    const desafio = l.json().desafio;

    // Não é possível pular o cadastro do autenticador.
    const skip = await app.inject({ method: 'POST', url: '/auth/mfa/verificar', remoteAddress: ip, payload: { desafio, codigo: '123456' } });
    expect(skip.statusCode).toBe(400);

    const setup = await app.inject({ method: 'POST', url: '/auth/mfa/cadastro', remoteAddress: ip, payload: { desafio } });
    expect(setup.json().otpauthUrl).toMatch(/^otpauth:\/\/totp\//);
    const v = await app.inject({
      method: 'POST', url: '/auth/mfa/verificar', remoteAddress: ip,
      payload: { desafio, codigo: codeAt(setup.json().segredo, currentStep()) },
    });
    expect(v.statusCode).toBe(200);
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: auth(v.json().accessToken) });
    expect(me.json().papel).toBe('MASTER');

    // Desafio já consumido não pode ser reutilizado.
    const again = await app.inject({ method: 'POST', url: '/auth/mfa/verificar', remoteAddress: ip, payload: { desafio, codigo: '000000' } });
    expect(again.statusCode).toBe(401);
  });

  it('mensagem genérica e bloqueio após 5 senhas erradas', async () => {
    const app = await getApp();
    const u = await createActiveUser({ role: 'MASTER' });
    const unknown = await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: nextIp(), payload: { email: 'nao.existe@teste.com.br', senha: 'x' } });
    for (let i = 0; i < 5; i++) {
      const r = await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: nextIp(), payload: { email: u.email, senha: 'errada' } });
      expect(r.statusCode).toBe(401);
      expect(r.json().mensagem).toBe(unknown.json().mensagem);
    }
    // Mesmo com a senha correta, a conta está bloqueada.
    const r = await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: nextIp(), payload: { email: u.email, senha: PASSWORD } });
    expect(r.statusCode).toBe(401);
    const { rows } = await ownerQuery(`SELECT count(*)::int AS n FROM audit_logs WHERE action = 'CONTA_BLOQUEADA' AND actor_user_id = $1`, [u.id]);
    expect(rows[0].n).toBe(1);
  });

  it('código TOTP errado e limite de tentativas por desafio', async () => {
    const app = await getApp();
    const u = await createActiveUser({ role: 'MASTER' });
    const ip = nextIp();
    const l = await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: ip, payload: { email: u.email, senha: PASSWORD } });
    const desafio = l.json().desafio;
    for (let i = 0; i < 5; i++) {
      const r = await app.inject({ method: 'POST', url: '/auth/mfa/verificar', remoteAddress: ip, payload: { desafio, codigo: '000000' } });
      expect(r.statusCode).toBe(401);
    }
    const r = await app.inject({ method: 'POST', url: '/auth/mfa/verificar', remoteAddress: ip, payload: { desafio, codigo: codeAt(u.secret, currentStep()) } });
    expect(r.statusCode).toBe(401);
  });

  it('limita tentativas de login por IP', async () => {
    const app = await getApp();
    const ip = nextIp();
    let last = 0;
    for (let i = 0; i < 11; i++) {
      last = (await app.inject({ method: 'POST', url: '/auth/login', remoteAddress: ip, payload: { email: 'x@teste.com.br', senha: 'x' } })).statusCode;
    }
    expect(last).toBe(429);
  });

  it('refresh: rotação, proteção CSRF e detecção de reuso', async () => {
    const app = await getApp();
    const u = await createActiveUser({ role: 'MASTER' });
    const { cookie } = await login(u);

    const noCsrf = await app.inject({ method: 'POST', url: '/auth/refresh', headers: { cookie } });
    expect(noCsrf.statusCode).toBe(403);

    const r1 = await app.inject({ method: 'POST', url: '/auth/refresh', headers: { cookie, 'x-csrf-protection': '1' } });
    expect(r1.statusCode).toBe(200);
    const sc = r1.headers['set-cookie'];
    const cookie2 = (Array.isArray(sc) ? sc[0] : sc)!.split(';')[0]!;
    expect(sc!.toString()).toMatch(/HttpOnly/i);
    expect(sc!.toString()).toMatch(/SameSite=Strict/i);

    // Reapresentar o token antigo derruba toda a família de sessões.
    const reuse = await app.inject({ method: 'POST', url: '/auth/refresh', headers: { cookie, 'x-csrf-protection': '1' } });
    expect(reuse.statusCode).toBe(401);
    const after = await app.inject({ method: 'POST', url: '/auth/refresh', headers: { cookie: cookie2, 'x-csrf-protection': '1' } });
    expect(after.statusCode).toBe(401);
    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: auth(r1.json().accessToken) });
    expect(me.statusCode).toBe(401);
  });

  it('logout revoga a sessão imediatamente', async () => {
    const app = await getApp();
    const u = await createActiveUser({ role: 'MASTER' });
    const { token } = await login(u);
    expect((await app.inject({ method: 'POST', url: '/auth/logout', headers: auth(token) })).statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(token) })).statusCode).toBe(401);
  });

  it('rejeita tokens adulterados', async () => {
    const app = await getApp();
    const u = await createActiveUser({ role: 'MASTER' });
    const { token } = await login(u);
    const [h, p, s] = token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), sub: '00000000-0000-0000-0000-000000000000' })).toString('base64url');
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(`${h}.${forged}.${s}`) })).statusCode).toBe(401);
    const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${p}.`;
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(none) })).statusCode).toBe(401);
  });

  it('alteração de senha encerra outras sessões', async () => {
    const app = await getApp();
    const admId = await createAdministradora();
    const u = await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: admId, nome: 'Fulano Teste' });
    const s1 = await login(u);
    const s2 = await login(u);
    const r = await app.inject({
      method: 'POST', url: '/auth/senha/alterar', headers: auth(s1.token),
      payload: { senhaAtual: PASSWORD, novaSenha: 'Outra$Chave-Forte99' },
    });
    expect(r.statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(s1.token) })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(s2.token) })).statusCode).toBe(401);
  });
});
