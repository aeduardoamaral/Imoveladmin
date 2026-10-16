import { beforeAll, describe, expect, it } from 'vitest';
import { withTx } from '../src/db.js';
import { auth, createActiveUser, createAdministradora, getApp, login, randomCnpj } from './helpers.js';

type Categoria = { id: string; nome: string; tipo: string };

describe('Financeiro da administradora', () => {
  let admId: string;
  let gestor: string;
  let colab: string;
  let master: string;
  let categorias: Categoria[];
  let contaId: string;
  let condominioId: string;
  const cat = (nome: string) => categorias.find((c) => c.nome.startsWith(nome))!.id;

  const req = async (token: string, method: 'GET' | 'POST' | 'PATCH', url: string, payload?: unknown) =>
    (await getApp()).inject({ method, url, headers: auth(token), payload: payload as never });

  beforeAll(async () => {
    admId = await createAdministradora('Imobiliária Financeira');
    gestor = (await login(await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: admId }))).token;
    colab = (await login(await createActiveUser({ role: 'ADMIN_COLABORADOR', administradoraId: admId }))).token;
    master = (await login(await createActiveUser({ role: 'MASTER' }))).token;
    categorias = (await req(colab, 'GET', '/financeiro/categorias')).json().dados;

    const conta = await req(gestor, 'POST', '/financeiro/contas', { nome: 'Banco Principal', tipo: 'CONTA_CORRENTE', banco: '077', saldoInicial: '10000.00', dataSaldoInicial: '2025-01-01' });
    expect(conta.statusCode).toBe(201);
    contaId = conta.json().id;
    condominioId = (await req(gestor, 'POST', '/condominios', { nome: 'Edifício Solar', cep: '01310100', logradouro: 'Rua A', numero: '10', bairro: 'Centro', cidade: 'São Paulo', uf: 'SP' })).json().id;
  });

  it('administradora nasce com plano de contas padrão e define o tipo de operação', async () => {
    expect(categorias.length).toBe(21);
    const r = await req(master, 'POST', '/administradoras', {
      razaoSocial: 'Só Locação Ltda', cnpj: randomCnpj(), email: 'loc@teste.com.br', operaCondominios: false, operaLocacao: true,
      gestor: { nome: 'Gestor Locação', email: 'gestor.locacao@teste.com.br' },
    });
    expect(r.statusCode).toBe(201);
    expect(r.json().administradora).toMatchObject({ operaCondominios: false, operaLocacao: true });
    const locId = r.json().administradora.id;
    expect((await req(master, 'GET', `/financeiro/categorias?administradoraId=${locId}`)).json().dados.length).toBe(21);
    const c = await req(master, 'POST', '/condominios', { administradoraId: locId, nome: 'X', cep: '01310100', logradouro: 'R', numero: '1', bairro: 'B', cidade: 'C', uf: 'SP' });
    expect(c.statusCode).toBe(400);
    const nenhuma = await req(master, 'POST', '/administradoras', {
      razaoSocial: 'Nada Ltda', cnpj: randomCnpj(), email: 'n@teste.com.br', operaCondominios: false, operaLocacao: false,
      gestor: { nome: 'Gestor Nada', email: 'gestor.nada@teste.com.br' },
    });
    expect(nenhuma.statusCode).toBe(400);
  });

  it('colaborador lança receitas e despesas, dá baixa; gestão estorna e cancela', async () => {
    const receita = await req(colab, 'POST', '/financeiro/lancamentos', {
      tipo: 'RECEITA', descricao: 'Taxa de administração set/2025', categoriaId: cat('Taxa de administração de condomínios'),
      condominioId, contraparte: 'Edifício Solar', valor: 5000, dataVencimento: '2025-09-10', pago: { dataPagamento: '2025-09-10', contaId },
    });
    expect(receita.statusCode).toBe(201);
    expect(receita.json()).toMatchObject({ status: 'PAGO', valorPago: '5000.00', dataPagamento: '2025-09-10', condominioNome: 'Edifício Solar' });

    const salario = await req(colab, 'POST', '/financeiro/lancamentos', {
      tipo: 'DESPESA', descricao: 'Folha set/2025', categoriaId: cat('Salários'), valor: '2000.10', dataVencimento: '2025-09-05',
    });
    expect(salario.json().situacao).toBe('ATRASADO');
    const baixa = await req(colab, 'POST', `/financeiro/lancamentos/${salario.json().id}/baixa`, { dataPagamento: '2025-09-06', contaId });
    expect(baixa.json()).toMatchObject({ status: 'PAGO', valorPago: '2000.10' });
    expect((await req(colab, 'PATCH', `/financeiro/lancamentos/${salario.json().id}`, { valor: 1 })).statusCode).toBe(409);

    // Imposto vencido e em aberto
    await req(colab, 'POST', '/financeiro/lancamentos', {
      tipo: 'DESPESA', descricao: 'Simples Nacional set/2025', categoriaId: cat('Impostos'), valor: 300, dataVencimento: '2025-10-20', dataCompetencia: '2025-09-30',
    });

    // Aluguel do escritório: 3 meses; cancela a partir do 2º
    const aluguel = await req(colab, 'POST', '/financeiro/lancamentos', {
      tipo: 'DESPESA', descricao: 'Aluguel escritório', categoriaId: cat('Aluguel e condomínio'), valor: 1500, dataVencimento: '2025-09-15', repetirMeses: 3,
    });
    const parcelas = aluguel.json().dados;
    expect(parcelas.map((x: { dataVencimento: string }) => x.dataVencimento)).toEqual(['2025-09-15', '2025-10-15', '2025-11-15']);
    expect((await req(colab, 'POST', `/financeiro/lancamentos/${parcelas[1].id}/cancelar`, { motivo: 'Mudança de escritório' })).statusCode).toBe(403);
    const canc = await req(gestor, 'POST', `/financeiro/lancamentos/${parcelas[1].id}/cancelar`, { motivo: 'Mudança de escritório', incluirParcelasFuturas: true });
    expect(canc.json().cancelados).toBe(2);

    // Estorno: somente gestão
    expect((await req(colab, 'POST', `/financeiro/lancamentos/${salario.json().id}/estorno`, { motivo: 'Lançado errado' })).statusCode).toBe(403);
    const est = await req(gestor, 'POST', `/financeiro/lancamentos/${salario.json().id}/estorno`, { motivo: 'Data errada' });
    expect(est.json()).toMatchObject({ status: 'PENDENTE', valorPago: null });
    await req(colab, 'POST', `/financeiro/lancamentos/${salario.json().id}/baixa`, { dataPagamento: '2025-09-06' });

    const lista = await req(colab, 'GET', '/financeiro/lancamentos?de=2025-09-01&ate=2025-09-30&campoData=competencia');
    expect(lista.json().totais).toEqual({ receitas: '5000.00', despesas: '3800.10' });
  });

  it('valida valores, tipo da categoria e referências de outra administradora', async () => {
    const base = { tipo: 'DESPESA', descricao: 'Teste', categoriaId: cat('Outras despesas'), valor: 10, dataVencimento: '2025-09-01' };
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, valor: 10.555 })).statusCode).toBe(400);
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, valor: 'abc' })).statusCode).toBe(400);
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, valor: 0 })).statusCode).toBe(400);
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, dataVencimento: '2025-02-30' })).statusCode).toBe(400);
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, tipo: 'RECEITA' })).statusCode).toBe(400);

    const outra = await createAdministradora('Concorrente');
    const outraCat = await withTx({ role: 'tenant', tenantId: outra }, async (tx) =>
      (await tx.query(`SELECT id FROM categorias_financeiras WHERE tipo = 'DESPESA' LIMIT 1`)).rows[0].id);
    expect((await req(colab, 'POST', '/financeiro/lancamentos', { ...base, categoriaId: outraCat })).statusCode).toBe(404);
    // Mesmo indo direto ao banco, a chave composta impede misturar administradoras.
    await expect(withTx({ role: 'tenant', tenantId: admId }, (tx) => tx.query(
      `INSERT INTO lancamentos (administradora_id, tipo, descricao, categoria_id, valor, data_competencia, data_vencimento)
       VALUES ($1, 'DESPESA', 'Teste FK', $2, 1, '2025-01-01', '2025-01-01')`, [admId, outraCat]))).rejects.toThrow(/foreign key/);
    const otherGestor = (await login(await createActiveUser({ role: 'ADMIN_GESTOR', administradoraId: outra }))).token;
    expect((await req(otherGestor, 'GET', '/financeiro/lancamentos')).json().total).toBe(0);
  });

  it('DRE por competência e por caixa', async () => {
    const comp = (await req(gestor, 'GET', '/financeiro/relatorios/dre?de=2025-09-01&ate=2025-09-30')).json();
    expect(comp.resultados).toMatchObject({
      receitaBruta: '5000.00', receitaLiquida: '4700.00', despesasOperacionais: '3500.10',
      resultadoOperacional: '1199.90', resultadoLiquido: '1199.90', margemLiquidaPercentual: '24.00',
    });
    const caixa = (await req(gestor, 'GET', '/financeiro/relatorios/dre?de=2025-09-01&ate=2025-09-30&regime=caixa')).json();
    expect(caixa.resultados.resultadoLiquido).toBe('2999.90');
    const porCond = (await req(gestor, 'GET', `/financeiro/relatorios/dre?de=2025-09-01&ate=2025-09-30&condominioId=${condominioId}`)).json();
    expect(porCond.resultados.resultadoLiquido).toBe('5000.00');
  });

  it('saldos, fluxo de caixa e painel gerencial', async () => {
    const saldos = (await req(gestor, 'GET', '/financeiro/relatorios/saldos')).json();
    expect(saldos.total).toBe('12999.90');

    const fluxo = (await req(gestor, 'GET', '/financeiro/relatorios/fluxo-caixa?deMes=2025-09&ateMes=2025-11')).json();
    expect(fluxo.saldoInicial).toBe('10000.00');
    expect(fluxo.meses[0]).toMatchObject({ mes: '2025-09', entradasRealizadas: '5000.00', saidasRealizadas: '2000.10', saidasPrevistas: '1500.00', saldoRealizado: '12999.90', saldoProjetado: '11499.90' });
    expect(fluxo.meses[1]).toMatchObject({ mes: '2025-10', saidasPrevistas: '300.00', saldoProjetado: '11199.90' });

    const d = (await req(gestor, 'GET', '/financeiro/dashboard?mes=2025-09')).json();
    expect(d.competencia).toMatchObject({ receitas: '5000.00', despesas: '3800.10', resultado: '1199.90' });
    expect(d.caixa).toMatchObject({ recebido: '5000.00', pago: '2000.10' });
    expect(d.aPagar).toMatchObject({ total: '1800.00', vencido: '1800.00', qtdVencidos: 2 });
    expect(d.serie12Meses).toHaveLength(12);
    expect(d.serie12Meses[11]).toMatchObject({ mes: '2025-09', receitas: '5000.00', resultado: '1199.90' });
    expect(d.porCondominio.find((c: { nome: string }) => c.nome === 'Edifício Solar')).toMatchObject({ receitas: '5000.00', resultado: '5000.00' });
    expect(d.saldos.total).toBe('12999.90');
  });

  it('painel e saldos são restritos à gestão; Master escolhe a administradora', async () => {
    expect((await req(colab, 'GET', '/financeiro/dashboard')).statusCode).toBe(403);
    expect((await req(colab, 'GET', '/financeiro/relatorios/dre')).statusCode).toBe(403);
    const contas = (await req(colab, 'GET', '/financeiro/contas')).json().dados;
    expect(contas[0].saldoInicial).toBeUndefined();
    expect((await req(colab, 'POST', '/financeiro/contas', { nome: 'Caixa 2', tipo: 'CAIXA' })).statusCode).toBe(403);
    expect((await req(master, 'GET', '/financeiro/dashboard')).statusCode).toBe(400);
    expect((await req(master, 'GET', `/financeiro/dashboard?administradoraId=${admId}&mes=2025-09`)).json().competencia.receitas).toBe('5000.00');
  });
});
