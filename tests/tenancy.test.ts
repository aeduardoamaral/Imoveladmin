import { beforeAll, describe, expect, it } from 'vitest';
import { withTx } from '../src/db.js';
import { auth, createActiveUser, getApp, login, PASSWORD, randomCnpj, type TestUser } from './helpers.js';

const condominio = (nome: string) => ({
  nome, cep: '01310-100', logradouro: 'Av. Paulista', numero: '1000', bairro: 'Bela Vista', cidade: 'São Paulo', uf: 'sp', numUnidades: 120,
});

describe('Master cadastra administradoras; administradoras cadastram condomínios', () => {
  let master: TestUser;
  let masterToken: string;
  let admA: string;
  let admB: string;
  let gestorA: { token: string };
  let gestorB: { token: string };
  let colabA: TestUser;

  async function newAdministradora(nome: string) {
    const app = await getApp();
    const r = await app.inject({
      method: 'POST', url: '/administradoras', headers: auth(masterToken),
      payload: {
        razaoSocial: nome, cnpj: randomCnpj(), email: 'contato@adm.com.br', uf: 'SP',
        gestor: { nome: `Gestor ${nome}`, email: `gestor.${nome.toLowerCase().replace(/\W/g, '')}@teste.com.br` },
      },
    });
    expect(r.statusCode).toBe(201);
    return r.json();
  }

  async function activateViaInvite(created: { convite: { url: string } }) {
    const app = await getApp();
    const token = created.convite.url.split("#")[1];
    expect((await app.inject({ method: "POST", url: "/auth/convite/aceitar", payload: { token, senha: PASSWORD } })).statusCode).toBe(200);
  }

  beforeAll(async () => {
    master = await createActiveUser({ role: 'MASTER' });
    masterToken = (await login(master)).token;
    const a = await newAdministradora('Administradora Alfa');
    const b = await newAdministradora('Administradora Beta');
    admA = a.administradora.id;
    admB = b.administradora.id;
    expect(a.gestor.status).toBe('PENDENTE');
    expect(a.convite.url).toMatch(/\/convite#/);
    await activateViaInvite(a);
    gestorA = await login(await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: admA }));
    gestorB = await login(await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: admB }));
    colabA = await createActiveUser({ role: 'ADMIN_COLABORADOR', administradoraId: admA });
  });

  it('somente o Master cadastra administradoras', async () => {
    const app = await getApp();
    const r = await app.inject({
      method: 'POST', url: '/administradoras', headers: auth(gestorA.token),
      payload: { razaoSocial: 'Intrusa', cnpj: randomCnpj(), email: 'x@x.com.br', gestor: { nome: 'X X', email: 'xx@teste.com.br' } },
    });
    expect(r.statusCode).toBe(403);
    expect((await app.inject({ method: 'GET', url: '/administradoras', headers: auth(gestorA.token) })).statusCode).toBe(403);
  });

  it('valida CNPJ e impede duplicidade', async () => {
    const app = await getApp();
    const bad = await app.inject({
      method: 'POST', url: '/administradoras', headers: auth(masterToken),
      payload: { razaoSocial: 'Ruim', cnpj: '11.111.111/1111-11', email: 'a@a.com.br', gestor: { nome: 'A A', email: 'aa@teste.com.br' } },
    });
    expect(bad.statusCode).toBe(400);
    const cnpj = randomCnpj();
    const payload = (e: string) => ({ razaoSocial: 'Dup', cnpj, email: 'a@a.com.br', gestor: { nome: 'A A', email: e } });
    expect((await app.inject({ method: 'POST', url: '/administradoras', headers: auth(masterToken), payload: payload('d1@teste.com.br') })).statusCode).toBe(201);
    expect((await app.inject({ method: 'POST', url: '/administradoras', headers: auth(masterToken), payload: payload('d2@teste.com.br') })).statusCode).toBe(409);
  });

  it('gestor cadastra condomínio na própria administradora; colaborador apenas consulta', async () => {
    const app = await getApp();
    const r = await app.inject({ method: 'POST', url: '/condominios', headers: auth(gestorA.token), payload: condominio('Residencial Alfa I') });
    expect(r.statusCode).toBe(201);
    expect(r.json().administradoraId).toBe(admA);
    expect(r.json().uf).toBe('SP');
    expect(r.json().cep).toBe('01310100');

    const colab = await login(colabA);
    expect((await app.inject({ method: 'POST', url: '/condominios', headers: auth(colab.token), payload: condominio('Proibido') })).statusCode).toBe(403);
    const list = await app.inject({ method: 'GET', url: '/condominios', headers: auth(colab.token) });
    expect(list.statusCode).toBe(200);
    expect(list.json().dados.map((c: { nome: string }) => c.nome)).toContain('Residencial Alfa I');
    expect((await app.inject({ method: 'GET', url: '/usuarios', headers: auth(colab.token) })).statusCode).toBe(403);
  });

  it('isolamento total entre administradoras', async () => {
    const app = await getApp();
    const cB = await app.inject({ method: 'POST', url: '/condominios', headers: auth(gestorB.token), payload: condominio('Condomínio Beta') });
    const idB = cB.json().id;

    // Leitura, alteração e listagem cruzadas são bloqueadas.
    expect((await app.inject({ method: 'GET', url: `/condominios/${idB}`, headers: auth(gestorA.token) })).statusCode).toBe(404);
    expect((await app.inject({ method: 'PATCH', url: `/condominios/${idB}`, headers: auth(gestorA.token), payload: { nome: 'Hackeado' } })).statusCode).toBe(404);
    expect((await app.inject({ method: 'GET', url: `/administradoras/${admB}`, headers: auth(gestorA.token) })).statusCode).toBe(404);
    const list = await app.inject({ method: 'GET', url: '/condominios', headers: auth(gestorA.token) });
    expect(list.json().dados.every((c: { administradoraId: string }) => c.administradoraId === admA)).toBe(true);
    expect((await app.inject({ method: 'GET', url: `/condominios?administradoraId=${admB}`, headers: auth(gestorA.token) })).statusCode).toBe(403);

    // Criação em outra administradora é recusada.
    expect((await app.inject({ method: 'POST', url: '/condominios', headers: auth(gestorA.token), payload: { ...condominio('X'), administradoraId: admB } })).statusCode).toBe(403);
    // Gestor não cria Master nem usuários em outra administradora.
    expect((await app.inject({ method: 'POST', url: '/usuarios', headers: auth(gestorA.token), payload: { nome: 'M M', email: 'mm@teste.com.br', papel: 'MASTER' } })).statusCode).toBe(403);
    expect((await app.inject({ method: 'POST', url: '/usuarios', headers: auth(gestorA.token), payload: { nome: 'M M', email: 'mm@teste.com.br', papel: 'ADMIN_GESTOR', administradoraId: admB } })).statusCode).toBe(403);

    // Master enxerga e opera em qualquer administradora.
    expect((await app.inject({ method: 'GET', url: `/condominios/${idB}`, headers: auth(masterToken) })).statusCode).toBe(200);
    const mc = await app.inject({ method: 'POST', url: '/condominios', headers: auth(masterToken), payload: { ...condominio('Criado pelo Master'), administradoraId: admB } });
    expect(mc.statusCode).toBe(201);
    expect((await app.inject({ method: 'POST', url: '/condominios', headers: auth(masterToken), payload: condominio('Sem adm') })).statusCode).toBe(400);
  });

  it('RLS no banco: contexto tenant só enxerga a própria administradora; sem contexto não enxerga nada', async () => {
    const own = await withTx({ role: 'tenant', tenantId: admA }, async (tx) => (await tx.query(`SELECT DISTINCT administradora_id FROM condominios`)).rows);
    expect(own.map((r) => r.administradora_id)).toEqual([admA]);
    const users = await withTx({ role: 'tenant', tenantId: admA }, async (tx) => (await tx.query(`SELECT role FROM users`)).rows);
    expect(users.some((u) => u.role === 'MASTER')).toBe(false);
    await expect(
      withTx({ role: 'tenant', tenantId: admA }, (tx) =>
        tx.query(`INSERT INTO condominios (administradora_id, nome, cep, logradouro, numero, bairro, cidade, uf) VALUES ($1,'X','01310100','R','1','B','C','SP')`, [admB])),
    ).rejects.toThrow(/row-level security/);
    await expect(
      withTx({ role: 'tenant', tenantId: admA }, (tx) => tx.query(`UPDATE users SET role = 'MASTER', administradora_id = NULL WHERE administradora_id = $1`, [admA])),
    ).rejects.toThrow();
    await expect(withTx({ role: 'tenant', tenantId: admA }, (tx) => tx.query(`SELECT * FROM sessions`))).resolves.toMatchObject({ rowCount: 0 });

    const pg = (await import('pg')).default;
    const c = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await c.connect();
    const none = await c.query(`SELECT count(*)::int AS n FROM condominios`);
    await c.end();
    expect(none.rows[0].n).toBe(0);
  });

  it('suspender a administradora derruba os acessos imediatamente', async () => {
    const app = await getApp();
    const created = await app.inject({
      method: 'POST', url: '/administradoras', headers: auth(masterToken),
      payload: { razaoSocial: 'Gama', cnpj: randomCnpj(), email: 'g@g.com.br', gestor: { nome: 'G G', email: 'gestor.gama@teste.com.br' } },
    });
    const admG = created.json().administradora.id;
    const g = await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: admG });
    const s = await login(g);
    expect((await app.inject({ method: 'GET', url: '/condominios', headers: auth(s.token) })).statusCode).toBe(200);

    const sus = await app.inject({ method: 'PATCH', url: `/administradoras/${admG}/status`, headers: auth(masterToken), payload: { status: 'SUSPENSA', motivo: 'Inadimplência contratual' } });
    expect(sus.statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/condominios', headers: auth(s.token) })).statusCode).toBe(401);
    expect((await app.inject({ method: 'POST', url: '/auth/refresh', headers: { cookie: s.cookie, 'x-csrf-protection': '1' } })).statusCode).toBe(401);
    expect((await app.inject({ method: 'POST', url: '/auth/login', payload: { email: g.email, senha: PASSWORD } })).statusCode).toBe(403);
  });

  it('gestor gerencia colaboradores: convite, suspensão e reset de MFA', async () => {
    const app = await getApp();
    const r = await app.inject({ method: 'POST', url: '/usuarios', headers: auth(gestorA.token), payload: { nome: 'Colaborador Novo', email: 'colab.novo@teste.com.br', papel: 'ADMIN_COLABORADOR', cpf: '529.982.247-25' } });
    expect(r.statusCode).toBe(201);
    expect(r.json().usuario.administradoraId).toBe(admA);
    const s = await login(colabA);
    expect((await app.inject({ method: 'PATCH', url: `/usuarios/${colabA.id}/status`, headers: auth(gestorA.token), payload: { status: 'SUSPENSO', motivo: 'Desligamento' } })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/condominios', headers: auth(s.token) })).statusCode).toBe(401);
    expect((await app.inject({ method: 'PATCH', url: `/usuarios/${colabA.id}/status`, headers: auth(gestorB.token), payload: { status: 'ATIVO', motivo: 'Tentativa indevida' } })).statusCode).toBe(404);
    expect((await app.inject({ method: 'PATCH', url: `/usuarios/${colabA.id}/status`, headers: auth(gestorA.token), payload: { status: 'ATIVO', motivo: 'Retorno' } })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: `/usuarios/${colabA.id}/mfa/resetar`, headers: auth(gestorB.token), payload: { motivo: 'Perdeu o celular' } })).statusCode).toBe(404);
    expect((await app.inject({ method: 'POST', url: `/usuarios/${colabA.id}/mfa/resetar`, headers: auth(gestorA.token), payload: { motivo: 'Perdeu o celular' } })).statusCode).toBe(200);
    const l = await app.inject({ method: 'POST', url: '/auth/login', payload: { email: colabA.email, senha: PASSWORD } });
    expect(l.json().etapa).toBe('MFA_CADASTRO');
  });
});
