import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../../audit.js';
import { authenticate, dbContext, requirePrincipal, requireRoles } from '../../auth/principal.js';
import { withTx, type Tx } from '../../db.js';
import { badRequest, HttpError, notFound } from '../../errors.js';
import { addMonths, buildUpdate, camel, optionalText, trimmed, zDate, zIdParam, zPage, zPositiveMoney, zUuid } from '../../http.js';
import { resolveAdministradora } from '../usuarios.js';

const zTipo = z.enum(['RECEITA', 'DESPESA']);

const SELECT = `
  SELECT l.id, l.administradora_id, l.tipo, l.descricao, l.categoria_id, c.nome AS categoria_nome, c.grupo AS categoria_grupo,
         l.conta_id, cf.nome AS conta_nome, l.condominio_id, co.nome AS condominio_nome,
         l.contraparte, l.documento, l.observacoes, l.valor, l.data_competencia, l.data_vencimento,
         l.status, l.data_pagamento, l.valor_pago,
         CASE WHEN l.status = 'PENDENTE' AND l.data_vencimento < current_date THEN 'ATRASADO' ELSE l.status END AS situacao,
         l.recorrencia_id, l.parcela, l.total_parcelas, l.created_by, l.updated_by, l.created_at, l.updated_at
    FROM lancamentos l
    JOIN categorias_financeiras c ON c.id = l.categoria_id
    LEFT JOIN contas_financeiras cf ON cf.id = l.conta_id
    LEFT JOIN condominios co ON co.id = l.condominio_id`;

async function loadLancamento(tx: Tx, id: string) {
  const { rows } = await tx.query(`SELECT * FROM lancamentos WHERE id = $1 FOR UPDATE`, [id]);
  if (!rows[0]) throw notFound('Lançamento não encontrado');
  return rows[0];
}

async function selectOne(tx: Tx, id: string) {
  const { rows } = await tx.query(`${SELECT} WHERE l.id = $1`, [id]);
  return camel(rows[0]);
}

/** Confere categoria, conta e condomínio (mesma administradora, ativos e coerentes com o tipo). */
async function validateRefs(
  tx: Tx,
  admId: string,
  tipo: string,
  refs: { categoriaId?: string; contaId?: string | null; condominioId?: string | null },
): Promise<void> {
  if (refs.categoriaId) {
    const { rows } = await tx.query(`SELECT tipo, ativo FROM categorias_financeiras WHERE id = $1 AND administradora_id = $2`, [refs.categoriaId, admId]);
    if (!rows[0]) throw notFound('Categoria não encontrada');
    if (!rows[0].ativo) throw badRequest('Categoria inativa');
    if (rows[0].tipo !== tipo) throw badRequest(`A categoria escolhida é de ${rows[0].tipo === 'RECEITA' ? 'receita' : 'despesa'}`);
  }
  if (refs.contaId) {
    const { rows } = await tx.query(`SELECT ativo FROM contas_financeiras WHERE id = $1 AND administradora_id = $2`, [refs.contaId, admId]);
    if (!rows[0]) throw notFound('Conta financeira não encontrada');
    if (!rows[0].ativo) throw badRequest('Conta financeira inativa');
  }
  if (refs.condominioId) {
    const { rows } = await tx.query(`SELECT 1 FROM condominios WHERE id = $1 AND administradora_id = $2`, [refs.condominioId, admId]);
    if (!rows[0]) throw notFound('Condomínio não encontrado');
  }
}

const baixaSchema = z.object({
  dataPagamento: zDate.optional(),
  valorPago: zPositiveMoney.optional(),
  contaId: zUuid.optional(),
});

export async function financeiroLancamentosRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  const gestao = requireRoles('MASTER', 'ADMIN_GESTOR');

  app.post('/financeiro/lancamentos', async (req, reply) => {
    const p = requirePrincipal(req);
    const body = z
      .object({
        administradoraId: zUuid.nullish(),
        tipo: zTipo,
        descricao: trimmed(200),
        categoriaId: zUuid,
        contaId: zUuid.nullish(),
        condominioId: zUuid.nullish(),
        contraparte: optionalText(200),
        documento: optionalText(60),
        observacoes: optionalText(2000),
        valor: zPositiveMoney,
        dataVencimento: zDate,
        dataCompetencia: zDate.optional(),
        // Lançamento mensal repetido (ex.: aluguel do escritório) - de 2 a 60 meses.
        repetirMeses: z.number().int().min(2).max(60).optional(),
        // Lançamento já pago/recebido no ato.
        pago: baixaSchema.optional(),
      })
      .parse(req.body);
    if (body.repetirMeses && body.pago) throw badRequest('Lançamentos repetidos são criados como pendentes');
    const admId = resolveAdministradora(p, body.administradoraId);

    const ids = await withTx(dbContext(p), async (tx) => {
      const contaPagamento = body.pago?.contaId ?? body.contaId ?? null;
      if (body.pago && !contaPagamento) throw badRequest('Informe a conta para lançamento já pago');
      await validateRefs(tx, admId, body.tipo, { categoriaId: body.categoriaId, contaId: contaPagamento, condominioId: body.condominioId });
      if (body.contaId && body.contaId !== contaPagamento) await validateRefs(tx, admId, body.tipo, { contaId: body.contaId });

      const total = body.repetirMeses ?? 1;
      const recorrenciaId = total > 1 ? randomUUID() : null;
      const competencia = body.dataCompetencia ?? body.dataVencimento;
      const created: string[] = [];
      for (let i = 0; i < total; i++) {
        const { rows } = await tx.query(
          `INSERT INTO lancamentos (administradora_id, tipo, descricao, categoria_id, conta_id, condominio_id, contraparte,
                                    documento, observacoes, valor, data_competencia, data_vencimento, status,
                                    data_pagamento, valor_pago, recorrencia_id, parcela, total_parcelas, created_by, updated_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19) RETURNING id`,
          [admId, body.tipo, body.descricao, body.categoriaId, contaPagamento, body.condominioId ?? null, body.contraparte ?? null,
            body.documento ?? null, body.observacoes ?? null, body.valor, addMonths(competencia, i), addMonths(body.dataVencimento, i),
            body.pago ? 'PAGO' : 'PENDENTE',
            body.pago ? (body.pago.dataPagamento ?? new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' })) : null,
            body.pago ? (body.pago.valorPago ?? body.valor) : null,
            recorrenciaId, total > 1 ? i + 1 : null, total > 1 ? total : null, p.userId],
        );
        created.push(rows[0].id);
      }
      await audit(tx, req, {
        action: 'LANCAMENTO_CRIADO', entity: 'lancamento', entityId: created[0], administradoraId: admId,
        details: { tipo: body.tipo, valor: body.valor, descricao: body.descricao, parcelas: total, pago: Boolean(body.pago), ids: created.length > 1 ? created : undefined },
      });
      const { rows } = await tx.query(`${SELECT} WHERE l.id = ANY($1) ORDER BY l.data_vencimento`, [created]);
      return rows.map(camel);
    });
    return reply.status(201).send(ids.length === 1 ? ids[0] : { dados: ids });
  });

  app.get('/financeiro/lancamentos', async (req) => {
    const p = requirePrincipal(req);
    const q = zPage
      .extend({
        administradoraId: zUuid.optional(),
        tipo: zTipo.optional(),
        situacao: z.enum(['PENDENTE', 'ATRASADO', 'PAGO', 'CANCELADO']).optional(),
        categoriaId: zUuid.optional(),
        contaId: zUuid.optional(),
        condominioId: zUuid.optional(),
        campoData: z.enum(['vencimento', 'competencia', 'pagamento']).default('vencimento'),
        de: zDate.optional(),
        ate: zDate.optional(),
        busca: z.string().trim().max(100).optional(),
      })
      .parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    return withTx(dbContext(p), async (tx) => {
      const params: unknown[] = [admId];
      const where = ['l.administradora_id = $1'];
      const add = (sql: string, v: unknown) => {
        params.push(v);
        where.push(sql.replaceAll('?', `$${params.length}`));
      };
      if (q.tipo) add('l.tipo = ?', q.tipo);
      if (q.situacao === 'ATRASADO') where.push(`l.status = 'PENDENTE' AND l.data_vencimento < current_date`);
      else if (q.situacao === 'PENDENTE') where.push(`l.status = 'PENDENTE' AND l.data_vencimento >= current_date`);
      else if (q.situacao) add('l.status = ?', q.situacao);
      if (q.categoriaId) add('l.categoria_id = ?', q.categoriaId);
      if (q.contaId) add('l.conta_id = ?', q.contaId);
      if (q.condominioId) add('l.condominio_id = ?', q.condominioId);
      const col = { vencimento: 'l.data_vencimento', competencia: 'l.data_competencia', pagamento: 'l.data_pagamento' }[q.campoData];
      if (q.de) add(`${col} >= ?`, q.de);
      if (q.ate) add(`${col} <= ?`, q.ate);
      if (q.busca) add(`(l.descricao ILIKE ? OR l.contraparte ILIKE ? OR l.documento ILIKE ?)`, `%${q.busca.replace(/[\\%_]/g, '\\$&')}%`);
      const w = `WHERE ${where.join(' AND ')}`;

      const { rows: [tot] } = await tx.query(
        `SELECT count(*)::int AS total,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'RECEITA' AND l.status <> 'CANCELADO'), 0)::numeric(14,2)::text AS receitas,
                COALESCE(sum(l.valor) FILTER (WHERE l.tipo = 'DESPESA' AND l.status <> 'CANCELADO'), 0)::numeric(14,2)::text AS despesas
           FROM lancamentos l ${w}`,
        params,
      );
      params.push(q.porPagina, (q.pagina - 1) * q.porPagina);
      const { rows } = await tx.query(
        `${SELECT} ${w} ORDER BY ${col} NULLS LAST, l.created_at LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return {
        dados: rows.map(camel),
        total: tot.total,
        totais: { receitas: tot.receitas, despesas: tot.despesas },
        pagina: q.pagina,
        porPagina: q.porPagina,
      };
    });
  });

  app.get('/financeiro/lancamentos/:id', async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(`${SELECT} WHERE l.id = $1`, [id]);
      if (!rows[0]) throw notFound('Lançamento não encontrado');
      return camel(rows[0]);
    });
  });

  // Somente lançamentos pendentes podem ser editados (pagos precisam de estorno antes).
  app.patch('/financeiro/lancamentos/:id', async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({
        descricao: trimmed(200),
        categoriaId: zUuid,
        contaId: zUuid.nullable(),
        condominioId: zUuid.nullable(),
        contraparte: optionalText(200),
        documento: optionalText(60),
        observacoes: optionalText(2000),
        valor: zPositiveMoney,
        dataVencimento: zDate,
        dataCompetencia: zDate,
      })
      .partial()
      .strict()
      .parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const current = await loadLancamento(tx, id);
      if (current.status !== 'PENDENTE') throw new HttpError(409, 'LANCAMENTO_FECHADO', 'Somente lançamentos pendentes podem ser alterados');
      await validateRefs(tx, current.administradora_id, current.tipo, body);
      const { sets, values } = buildUpdate(
        body,
        {
          descricao: 'descricao', categoriaId: 'categoria_id', contaId: 'conta_id', condominioId: 'condominio_id',
          contraparte: 'contraparte', documento: 'documento', observacoes: 'observacoes', valor: 'valor',
          dataVencimento: 'data_vencimento', dataCompetencia: 'data_competencia',
        },
        3,
      );
      if (sets.length) {
        await tx.query(`UPDATE lancamentos SET ${sets.join(', ')}, updated_by = $2 WHERE id = $1`, [id, p.userId, ...values]);
        const before: Record<string, unknown> = {};
        for (const k of Object.keys(body)) before[k] = current[k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)];
        await audit(tx, req, { action: 'LANCAMENTO_ALTERADO', entity: 'lancamento', entityId: id, administradoraId: current.administradora_id, details: { antes: before, depois: body } });
      }
      return selectOne(tx, id);
    });
  });

  // Baixa: registra o pagamento (despesa) ou recebimento (receita).
  app.post('/financeiro/lancamentos/:id/baixa', async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = baixaSchema.parse(req.body ?? {});
    return withTx(dbContext(p), async (tx) => {
      const current = await loadLancamento(tx, id);
      if (current.status !== 'PENDENTE') throw new HttpError(409, 'LANCAMENTO_FECHADO', 'Lançamento não está pendente');
      const contaId = body.contaId ?? current.conta_id;
      if (!contaId) throw badRequest('Informe a conta de pagamento/recebimento');
      await validateRefs(tx, current.administradora_id, current.tipo, { contaId });
      const valorPago = body.valorPago ?? current.valor;
      await tx.query(
        `UPDATE lancamentos SET status = 'PAGO', conta_id = $2, data_pagamento = COALESCE($3::date, current_date), valor_pago = $4, updated_by = $5
          WHERE id = $1`,
        [id, contaId, body.dataPagamento ?? null, valorPago, p.userId],
      );
      await audit(tx, req, { action: 'LANCAMENTO_BAIXADO', entity: 'lancamento', entityId: id, administradoraId: current.administradora_id, details: { valor: current.valor, valorPago, contaId } });
      return selectOne(tx, id);
    });
  });

  // Estorno de baixa: volta o lançamento para pendente (somente gestão).
  app.post('/financeiro/lancamentos/:id/estorno', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z.object({ motivo: z.string().trim().min(5).max(500) }).parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const current = await loadLancamento(tx, id);
      if (current.status !== 'PAGO') throw new HttpError(409, 'LANCAMENTO_NAO_PAGO', 'Somente lançamentos pagos podem ser estornados');
      await tx.query(
        `UPDATE lancamentos SET status = 'PENDENTE', data_pagamento = NULL, valor_pago = NULL, updated_by = $2 WHERE id = $1`,
        [id, p.userId],
      );
      await audit(tx, req, {
        action: 'LANCAMENTO_ESTORNADO', entity: 'lancamento', entityId: id, administradoraId: current.administradora_id,
        details: { motivo: body.motivo, dataPagamento: current.data_pagamento, valorPago: current.valor_pago, contaId: current.conta_id },
      });
      return selectOne(tx, id);
    });
  });

  // Cancelamento (somente gestão). Opcionalmente cancela as parcelas futuras da mesma série.
  app.post('/financeiro/lancamentos/:id/cancelar', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({ motivo: z.string().trim().min(5).max(500), incluirParcelasFuturas: z.boolean().default(false) })
      .parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const current = await loadLancamento(tx, id);
      if (current.status !== 'PENDENTE') throw new HttpError(409, 'LANCAMENTO_FECHADO', 'Somente lançamentos pendentes podem ser cancelados');
      const { rows } = await tx.query(
        `UPDATE lancamentos SET status = 'CANCELADO', updated_by = $2
          WHERE status = 'PENDENTE' AND (id = $1 OR ($3 AND recorrencia_id = $4 AND parcela > $5))
          RETURNING id`,
        [id, p.userId, body.incluirParcelasFuturas && current.recorrencia_id !== null, current.recorrencia_id, current.parcela ?? 0],
      );
      await audit(tx, req, {
        action: 'LANCAMENTO_CANCELADO', entity: 'lancamento', entityId: id, administradoraId: current.administradora_id,
        details: { motivo: body.motivo, valor: current.valor, cancelados: rows.length },
      });
      return { cancelados: rows.length, lancamento: await selectOne(tx, id) };
    });
  });
}
