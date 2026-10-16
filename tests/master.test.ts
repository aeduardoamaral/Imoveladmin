import { describe, expect, it } from 'vitest';
import { auth, createActiveUser, createAdministradora, getApp, login, ownerQuery, PASSWORD } from './helpers.js';

describe('Master: acesso assistido e auditoria', () => {
  it('Master entra na conta de um usuário, ações ficam auditadas em seu nome e há limites', async () => {
    const app = await getApp();
    const master = await createActiveUser({ role: 'MASTER' });
    const otherMaster = await createActiveUser({ role: 'MASTER' });
    const adm = await createAdministradora('Adm Assistida');
    const gestor = await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: adm });
    const { token } = await login(master);

    expect((await app.inject({ method: 'POST', url: '/master/acesso-assistido', headers: auth(token), payload: { usuarioId: gestor.id, motivo: 'curto' } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url: '/master/acesso-assistido', headers: auth(token), payload: { usuarioId: otherMaster.id, motivo: 'Suporte solicitado pelo cliente' } })).statusCode).toBe(400);

    const imp = await app.inject({ method: 'POST', url: '/master/acesso-assistido', headers: auth(token), payload: { usuarioId: gestor.id, motivo: 'Suporte solicitado pelo cliente (chamado 123)' } });
    expect(imp.statusCode).toBe(200);
    const impToken = imp.json().accessToken;

    const me = await app.inject({ method: 'GET', url: '/auth/me', headers: auth(impToken) });
    expect(me.json()).toMatchObject({ id: gestor.id, acessoAssistidoPor: master.id, papel: 'ADMIN_GESTOR' });

    const c = await app.inject({
      method: 'POST', url: '/condominios', headers: auth(impToken),
      payload: { nome: 'Via acesso assistido', cep: '20040020', logradouro: 'Rua X', numero: '1', bairro: 'Centro', cidade: 'Rio de Janeiro', uf: 'RJ' },
    });
    expect(c.statusCode).toBe(201);
    const { rows } = await ownerQuery(`SELECT actor_user_id, impersonator_id FROM audit_logs WHERE action = 'CONDOMINIO_CRIADO' AND entity_id = $1`, [c.json().id]);
    expect(rows[0]).toMatchObject({ actor_user_id: gestor.id, impersonator_id: master.id });

    // Operações pessoais/sensíveis bloqueadas durante o acesso assistido.
    expect((await app.inject({ method: 'POST', url: '/auth/senha/alterar', headers: auth(impToken), payload: { senhaAtual: PASSWORD, novaSenha: 'Nova#Senha-Forte-1' } })).statusCode).toBe(403);
    expect((await app.inject({ method: 'GET', url: '/master/auditoria', headers: auth(impToken) })).statusCode).toBe(403);

    // Se o Master for suspenso, o acesso assistido cai junto.
    await ownerQuery(`UPDATE users SET status = 'SUSPENSO' WHERE id = $1`, [master.id]);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(impToken) })).statusCode).toBe(401);
    await ownerQuery(`UPDATE users SET status = 'ATIVO' WHERE id = $1`, [master.id]);
  });

  it('somente Master acessa a auditoria; trilha é imutável e verificável', async () => {
    const app = await getApp();
    const master = await createActiveUser({ role: 'MASTER' });
    const adm = await createAdministradora();
    const gestor = await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: adm });
    const { token } = await login(master);
    const g = await login(gestor);
    expect((await app.inject({ method: 'GET', url: '/master/auditoria', headers: auth(g.token) })).statusCode).toBe(403);

    const list = await app.inject({ method: 'GET', url: `/master/auditoria?usuarioId=${master.id}&acao=LOGIN_SUCESSO`, headers: auth(token) });
    expect(list.statusCode).toBe(200);
    expect(list.json().dados.length).toBeGreaterThan(0);

    const ok = await app.inject({ method: 'GET', url: '/master/auditoria/integridade', headers: auth(token) });
    expect(ok.json().integra).toBe(true);

    // Nem o papel da aplicação nem o dono conseguem alterar/apagar registros.
    const pg = (await import('pg')).default;
    const c = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await c.connect();
    await c.query(`SELECT set_config('app.role', 'master', false)`);
    await expect(c.query(`UPDATE audit_logs SET action = 'X'`)).rejects.toThrow();
    await expect(c.query(`DELETE FROM audit_logs`)).rejects.toThrow();
    await c.end();
    await expect(ownerQuery(`DELETE FROM audit_logs`)).rejects.toThrow(/append-only/);

    // Adulteração direta (desligando o gatilho) é detectada pela verificação da cadeia.
    const { rows } = await ownerQuery(`SELECT id, action FROM audit_logs ORDER BY id LIMIT 1`);
    await ownerQuery(`ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_no_update`);
    await ownerQuery(`UPDATE audit_logs SET action = 'ADULTERADO' WHERE id = $1`, [rows[0].id]);
    const broken = await app.inject({ method: 'GET', url: '/master/auditoria/integridade', headers: auth(token) });
    expect(broken.json()).toMatchObject({ integra: false, quebraNoRegistro: String(rows[0].id) });
    await ownerQuery(`UPDATE audit_logs SET action = $2 WHERE id = $1`, [rows[0].id, rows[0].action]);
    await ownerQuery(`ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_no_update`);
    expect((await app.inject({ method: 'GET', url: '/master/auditoria/integridade', headers: auth(token) })).json().integra).toBe(true);
  });

  it('Master lista e revoga sessões', async () => {
    const app = await getApp();
    const master = await createActiveUser({ role: 'MASTER' });
    const adm = await createAdministradora();
    const gestor = await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: adm });
    const { token } = await login(master);
    const g = await login(gestor);
    const list = await app.inject({ method: 'GET', url: `/master/sessoes?usuarioId=${gestor.id}`, headers: auth(token) });
    const sid = list.json().dados[0].id;
    expect((await app.inject({ method: 'POST', url: `/master/sessoes/${sid}/revogar`, headers: auth(token) })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: auth(g.token) })).statusCode).toBe(401);
  });
});
