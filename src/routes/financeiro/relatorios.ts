import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate, dbContext, requirePrincipal, requireRoles } from '../../auth/principal.js';
import { withTx, type Tx } from '../../db.js';
import { badRequest } from '../../errors.js';
import { addDays, addMonths, camel, lastDayOfMonth, zDate, zMes, zUuid } from '../../http.js';
import { resolveAdministradora } from '../usuarios.js';

// Aritmética em centavos (inteiros) para não acumular erro de ponto flutuante.
const toCents = (v: string | null | undefined): number => {
  if (!v) return 0;
  const neg = v.startsWith('-');
  const [i, d = ''] = (neg ? v.slice(1) : v).split('.');
  const cents = Number(i) * 100 + Number(d.padEnd(2, '0').slice(0, 2));
  return neg ? -cents : cents;
};
const money = (cents: number): string => {
  const neg = cents < 0;
  const abs = Math.abs(cents);
  return `${neg ? '-' : ''}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, '0')}`;
};
const pct = (part: number, whole: number): string | null => (whole === 0 ? null : ((part / whole) * 100).toFixed(2));

const hoje = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
const mesAtual = () => hoje().slice(0, 7);
const ultimoDia = lastDayOfMonth;

const DRE_GRUPOS = [
  { grupo: 'RECEITA_OPERACIONAL', titulo: 'Receita bruta de serviços', sinal: 1 },
  { grupo: 'DEDUCOES', titulo: '(-) Deduções e impostos sobre o faturamento', sinal: -1 },
  { grupo: 'DESPESA_PESSOAL', titulo: '(-) Despesas com pessoal', sinal: -1 },
  { grupo: 'DESPESA_ADMINISTRATIVA', titulo: '(-) Despesas administrativas', sinal: -1 },
  { grupo: 'DESPESA_COMERCIAL', titulo: '(-) Despesas comerciais', sinal: -1 },
  { grupo: 'RECEITA_FINANCEIRA', titulo: '(+) Receitas financeiras', sinal: 1 },
  { grupo: 'DESPESA_FINANCEIRA', titulo: '(-) Despesas financeiras', sinal: -1 },
  { grupo: 'OUTRAS_RECEITAS', titulo: '(+) Outras receitas', sinal: 1 },
  { grupo: 'OUTRAS_DESPESAS', titulo: '(-) Outras despesas', sinal: -1 },
] as const;

type Regime = 'competencia' | 'caixa';

/** Condição e coluna de valor de acordo com o regime (competência ou caixa). */
function regimeSql(regime: Regime) {
  return regime === 'caixa'
    ? { filtro: `l.status = 'PAGO'`, data: 'l.data_pagamento', valor: 'l.valor_pago' }
    : { filtro: `l.status <> 'CANCELADO'`, data: 'l.data_competencia', valor: 'l.valor' };
}

async function saldosContas(tx: Tx, admId: string, ate: string) {
  const { rows } = await tx.query(
    `SELECT c.id, c.nome, c.tipo, c.ativo,
            (CASE WHEN c.data_saldo_inicial <= $2 THEN c.saldo_inicial ELSE 0 END + COALESCE(sum(CASE WHEN l.tipo = 'RECEITA' THEN l.valor_pago ELSE -l.valor_pago END), 0))::numeric(14,2)::text AS saldo
       FROM contas_financeiras c
       LEFT JOIN lancamentos l ON l.conta_id = c.id AND l.status = 'PAGO'
            AND l.data_pagamento >= c.data_saldo_inicial AND l.data_pagamento <= $2
      WHERE c.administradora_id = $1
      GROUP BY c.id ORDER BY c.nome`,
    [admId, ate],
  );
  const total = rows.reduce((acc, r) => acc + toCents(r.saldo), 0);
  return { contas: rows.map(camel), total: money(total) };
}

async function dre(tx: Tx, admId: string, de: string, ate: string, regime: Regime, condominioId?: string) {
  const r = regimeSql(regime);
  const { rows } = await tx.query(
    `SELECT c.grupo, c.id, c.nome, COALESCE(sum(${r.valor}), 0)::numeric(14,2)::text AS total
       FROM lancamentos l JOIN categorias_financeiras c ON c.id = l.categoria_id
      WHERE l.administradora_id = $1 AND ${r.filtro} AND ${r.data} BETWEEN $2 AND $3
        AND ($4::uuid IS NULL OR l.condominio_id = $4)
      GROUP BY c.grupo, c.id, c.nome ORDER BY c.nome`,
    [admId, de, ate, condominioId ?? null],
  );
  const byGroup = new Map<string, { id: string; nome: string; total: string }[]>();
  for (const row of rows) {
    const list = byGroup.get(row.grupo) ?? [];
    list.push({ id: row.id, nome: row.nome, total: row.total });
    byGroup.set(row.grupo, list);
  }
  const g: Record<string, number> = {};
  const linhas = DRE_GRUPOS.map(({ grupo, titulo }) => {
    const categorias = byGroup.get(grupo) ?? [];
    g[grupo] = categorias.reduce((a, c) => a + toCents(c.total), 0);
    return { grupo, titulo, total: money(g[grupo]), categorias };
  });
  const v = (k: string) => g[k] ?? 0;
  const receitaBruta = v('RECEITA_OPERACIONAL');
  const receitaLiquida = receitaBruta - v('DEDUCOES');
  const despesasOperacionais = v('DESPESA_PESSOAL') + v('DESPESA_ADMINISTRATIVA') + v('DESPESA_COMERCIAL');
  const resultadoOperacional = receitaLiquida - despesasOperacionais;
  const resultadoFinanceiro = v('RECEITA_FINANCEIRA') - v('DESPESA_FINANCEIRA');
  const outrosResultados = v('OUTRAS_RECEITAS') - v('OUTRAS_DESPESAS');
  const resultadoLiquido = resultadoOperacional + resultadoFinanceiro + outrosResultados;
  return {
    periodo: { de, ate },
    regime,
    linhas,
    resultados: {
      receitaBruta: money(receitaBruta),
      receitaLiquida: money(receitaLiquida),
      despesasOperacionais: money(despesasOperacionais),
      resultadoOperacional: money(resultadoOperacional),
      resultadoFinanceiro: money(resultadoFinanceiro),
      outrosResultados: money(outrosResultados),
      resultadoLiquido: money(resultadoLiquido),
      margemLiquidaPercentual: pct(resultadoLiquido, receitaBruta),
    },
  };
}

export async function financeiroRelatoriosRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  // Relatórios e painel são informação gerencial: proprietários/gerentes (gestor) e Master.
  app.addHook('preHandler', requireRoles('MASTER', 'ADMIN_GESTOR'));

  app.get('/financeiro/relatorios/saldos', async (req) => {
    const p = requirePrincipal(req);
    const q = z.object({ administradoraId: zUuid.optional(), data: zDate.optional() }).parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    return withTx(dbContext(p), async (tx) => ({ data: q.data ?? hoje(), ...(await saldosContas(tx, admId, q.data ?? hoje())) }));
  });

  // DRE gerencial / balancete por categoria
  app.get('/financeiro/relatorios/dre', async (req) => {
    const p = requirePrincipal(req);
    const q = z
      .object({
        administradoraId: zUuid.optional(),
        de: zDate.optional(),
        ate: zDate.optional(),
        regime: z.enum(['competencia', 'caixa']).default('competencia'),
        condominioId: zUuid.optional(),
      })
      .parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    const de = q.de ?? `${mesAtual()}-01`;
    const ate = q.ate ?? ultimoDia(mesAtual());
    if (de > ate) throw badRequest('Período inválido');
    return withTx(dbContext(p), (tx) => dre(tx, admId, de, ate, q.regime, q.condominioId));
  });

  // Fluxo de caixa mensal: realizado + previsto, com saldo acumulado.
  app.get('/financeiro/relatorios/fluxo-caixa', async (req) => {
    const p = requirePrincipal(req);
    const q = z.object({ administradoraId: zUuid.optional(), deMes: zMes.optional(), ateMes: zMes.optional() }).parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    const deMes = q.deMes ?? addMonths(`${mesAtual()}-01`, -5).slice(0, 7);
    const ateMes = q.ateMes ?? addMonths(`${mesAtual()}-01`, 6).slice(0, 7);
    if (deMes > ateMes) throw badRequest('Período inválido');
    if (addMonths(`${deMes}-01`, 36) <= `${ateMes}-01`) throw badRequest('Período máximo de 36 meses');
    const inicio = `${deMes}-01`;
    const fim = ultimoDia(ateMes);

    return withTx(dbContext(p), async (tx) => {
      const { total: saldoAnterior } = await saldosContas(tx, admId, addDays(inicio, -1));
      const { rows } = await tx.query(
        `SELECT to_char(m, 'YYYY-MM') AS mes,
                COALESCE(sum(l.valor_pago) FILTER (WHERE l.status = 'PAGO' AND l.tipo = 'RECEITA' AND date_trunc('month', l.data_pagamento) = m), 0)::numeric(14,2)::text AS entradas_realizadas,
                COALESCE(sum(l.valor_pago) FILTER (WHERE l.status = 'PAGO' AND l.tipo = 'DESPESA' AND date_trunc('month', l.data_pagamento) = m), 0)::numeric(14,2)::text AS saidas_realizadas,
                COALESCE(sum(l.valor) FILTER (WHERE l.status = 'PENDENTE' AND l.tipo = 'RECEITA' AND date_trunc('month', l.data_vencimento) = m), 0)::numeric(14,2)::text AS entradas_previstas,
                COALESCE(sum(l.valor) FILTER (WHERE l.status = 'PENDENTE' AND l.tipo = 'DESPESA' AND date_trunc('month', l.data_vencimento) = m), 0)::numeric(14,2)::text AS saidas_previstas
           FROM generate_series($2::date, $3::date, interval '1 month') AS m
           LEFT JOIN lancamentos l ON l.administradora_id = $1 AND l.status <> 'CANCELADO'
                AND (date_trunc('month', l.data_pagamento) = m OR date_trunc('month', l.data_vencimento) = m)
          GROUP BY m ORDER BY m`,
        [admId, inicio, `${ateMes}-01`],
      );
      let realizado = toCents(saldoAnterior);
      let projetado = realizado;
      const meses = rows.map((r) => {
        const netReal = toCents(r.entradas_realizadas) - toCents(r.saidas_realizadas);
        const netPrev = toCents(r.entradas_previstas) - toCents(r.saidas_previstas);
        realizado += netReal;
        projetado += netReal + netPrev;
        return { ...camel(r), saldoRealizado: money(realizado), saldoProjetado: money(projetado) };
      });
      return { periodo: { de: inicio, ate: fim }, saldoInicial: saldoAnterior, meses };
    });
  });

  // Painel gerencial do negócio
  app.get('/financeiro/dashboard', async (req) => {
    const p = requirePrincipal(req);
    const q = z.object({ administradoraId: zUuid.optional(), mes: zMes.optional() }).parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    const mes = q.mes ?? mesAtual();
    const inicio = `${mes}-01`;
    const fim = ultimoDia(mes);
    const inicioSerie = addMonths(inicio, -11);

    return withTx(dbContext(p), async (tx) => {
      const competencia = await dre(tx, admId, inicio, fim, 'competencia');
      const caixa = await dre(tx, admId, inicio, fim, 'caixa');

      const { rows: [pend] } = await tx.query(
        `SELECT
           COALESCE(sum(valor) FILTER (WHERE tipo = 'RECEITA'), 0)::numeric(14,2)::text AS receber_total,
           COALESCE(sum(valor) FILTER (WHERE tipo = 'RECEITA' AND data_vencimento < current_date), 0)::numeric(14,2)::text AS receber_vencido,
           count(*) FILTER (WHERE tipo = 'RECEITA' AND data_vencimento < current_date)::int AS receber_qtd_vencidos,
           COALESCE(sum(valor) FILTER (WHERE tipo = 'DESPESA'), 0)::numeric(14,2)::text AS pagar_total,
           COALESCE(sum(valor) FILTER (WHERE tipo = 'DESPESA' AND data_vencimento < current_date), 0)::numeric(14,2)::text AS pagar_vencido,
           count(*) FILTER (WHERE tipo = 'DESPESA' AND data_vencimento < current_date)::int AS pagar_qtd_vencidos,
           COALESCE(sum(valor) FILTER (WHERE tipo = 'RECEITA' AND data_vencimento BETWEEN current_date AND current_date + 30), 0)::numeric(14,2)::text AS receber_30d,
           COALESCE(sum(valor) FILTER (WHERE tipo = 'DESPESA' AND data_vencimento BETWEEN current_date AND current_date + 30), 0)::numeric(14,2)::text AS pagar_30d
         FROM lancamentos WHERE administradora_id = $1 AND status = 'PENDENTE'`,
        [admId],
      );

      const { rows: serie } = await tx.query(
        `SELECT to_char(m, 'YYYY-MM') AS mes,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'RECEITA'), 0)::numeric(14,2)::text AS receitas,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'DESPESA'), 0)::numeric(14,2)::text AS despesas
           FROM generate_series($2::date, $3::date, interval '1 month') AS m
           LEFT JOIN lancamentos l ON l.administradora_id = $1 AND l.status <> 'CANCELADO'
                AND date_trunc('month', l.data_competencia) = m
          GROUP BY m ORDER BY m`,
        [admId, inicioSerie, inicio],
      );

      const { rows: porCondominio } = await tx.query(
        `SELECT l.condominio_id, COALESCE(co.nome, 'Sem vínculo com condomínio') AS nome,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'RECEITA'), 0)::numeric(14,2)::text AS receitas,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'DESPESA'), 0)::numeric(14,2)::text AS despesas
           FROM lancamentos l LEFT JOIN condominios co ON co.id = l.condominio_id
          WHERE l.administradora_id = $1 AND l.status <> 'CANCELADO' AND l.data_competencia BETWEEN $2 AND $3
          GROUP BY l.condominio_id, co.nome
          ORDER BY sum(l.valor) FILTER (WHERE l.tipo = 'RECEITA') DESC NULLS LAST`,
        [admId, inicio, fim],
      );

      const { rows: proximos } = await tx.query(
        `SELECT l.id, l.tipo, l.descricao, l.contraparte, l.valor, l.data_vencimento,
                (l.data_vencimento < current_date) AS vencido
           FROM lancamentos l
          WHERE l.administradora_id = $1 AND l.status = 'PENDENTE'
          ORDER BY l.data_vencimento LIMIT 10`,
        [admId],
      );

      const despesasPorGrupo = competencia.linhas
        .filter((l) => l.grupo.startsWith('DESPESA') || l.grupo === 'DEDUCOES' || l.grupo === 'OUTRAS_DESPESAS')
        .map((l) => ({ grupo: l.grupo, titulo: l.titulo.replace(/^\(-\) /, ''), total: l.total }));

      const somaReceitas = (d: typeof competencia) =>
        money(d.linhas.filter((l) => ['RECEITA_OPERACIONAL', 'RECEITA_FINANCEIRA', 'OUTRAS_RECEITAS'].includes(l.grupo)).reduce((a, l) => a + toCents(l.total), 0));
      const somaDespesas = (d: typeof competencia) =>
        money(d.linhas.filter((l) => !['RECEITA_OPERACIONAL', 'RECEITA_FINANCEIRA', 'OUTRAS_RECEITAS'].includes(l.grupo)).reduce((a, l) => a + toCents(l.total), 0));

      return {
        mes,
        competencia: {
          receitas: somaReceitas(competencia),
          despesas: somaDespesas(competencia),
          resultado: competencia.resultados.resultadoLiquido,
          margemLiquidaPercentual: competencia.resultados.margemLiquidaPercentual,
        },
        caixa: {
          recebido: somaReceitas(caixa),
          pago: somaDespesas(caixa),
          resultado: caixa.resultados.resultadoLiquido,
        },
        aReceber: { total: pend.receber_total, vencido: pend.receber_vencido, qtdVencidos: pend.receber_qtd_vencidos, proximos30Dias: pend.receber_30d },
        aPagar: { total: pend.pagar_total, vencido: pend.pagar_vencido, qtdVencidos: pend.pagar_qtd_vencidos, proximos30Dias: pend.pagar_30d },
        saldos: await saldosContas(tx, admId, hoje()),
        serie12Meses: serie.map((s) => ({ ...s, resultado: money(toCents(s.receitas) - toCents(s.despesas)) })),
        despesasPorGrupo,
        porCondominio: porCondominio.map((r) => ({ ...camel(r), resultado: money(toCents(r.receitas) - toCents(r.despesas)) })),
        proximosVencimentos: proximos.map(camel),
      };
    });
  });
}
