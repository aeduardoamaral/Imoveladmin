import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../../audit.js';
import { authenticate, dbContext, requirePrincipal, requireRoles } from '../../auth/principal.js';
import { withTx } from '../../db.js';
import { notFound } from '../../errors.js';
import { buildUpdate, camel, optionalText, trimmed, zDate, zIdParam, zMoney, zQueryBool, zUuid } from '../../http.js';
import { resolveAdministradora } from '../usuarios.js';

export const GRUPOS_RECEITA = ['RECEITA_OPERACIONAL', 'RECEITA_FINANCEIRA', 'OUTRAS_RECEITAS'] as const;
export const GRUPOS_DESPESA = ['DEDUCOES', 'DESPESA_PESSOAL', 'DESPESA_ADMINISTRATIVA', 'DESPESA_COMERCIAL', 'DESPESA_FINANCEIRA', 'OUTRAS_DESPESAS'] as const;

const CAT_COLUMNS = `id, administradora_id, nome, tipo, grupo, ativo, created_at, updated_at`;
const CONTA_COLUMNS = `id, administradora_id, nome, tipo, banco, agencia, numero, saldo_inicial, data_saldo_inicial, ativo, created_at, updated_at`;

const zAdmQuery = z.object({ administradoraId: zUuid.optional() });

export async function financeiroCadastrosRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', authenticate);
  const gestao = requireRoles('MASTER', 'ADMIN_GESTOR');

  // -------------------------------------------------------------------
  // Plano de contas
  // -------------------------------------------------------------------
  app.get('/financeiro/categorias', async (req) => {
    const p = requirePrincipal(req);
    const q = zAdmQuery
      .extend({ tipo: z.enum(['RECEITA', 'DESPESA']).optional(), incluirInativas: zQueryBool.default(false) })
      .parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `SELECT ${CAT_COLUMNS} FROM categorias_financeiras
          WHERE administradora_id = $1 AND ($2::text IS NULL OR tipo = $2) AND ($3 OR ativo)
          ORDER BY tipo DESC, grupo, nome`,
        [admId, q.tipo ?? null, q.incluirInativas],
      );
      return { dados: rows.map(camel) };
    });
  });

  app.post('/financeiro/categorias', { preHandler: gestao }, async (req, reply) => {
    const p = requirePrincipal(req);
    const body = z
      .discriminatedUnion('tipo', [
        z.object({ tipo: z.literal('RECEITA'), grupo: z.enum(GRUPOS_RECEITA) }),
        z.object({ tipo: z.literal('DESPESA'), grupo: z.enum(GRUPOS_DESPESA) }),
      ])
      .and(z.object({ nome: trimmed(120), administradoraId: zUuid.nullish() }))
      .parse(req.body);
    const admId = resolveAdministradora(p, body.administradoraId);
    const row = await withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `INSERT INTO categorias_financeiras (administradora_id, nome, tipo, grupo, created_by)
         VALUES ($1, $2, $3, $4, $5) RETURNING ${CAT_COLUMNS}`,
        [admId, body.nome, body.tipo, body.grupo, p.userId],
      );
      await audit(tx, req, { action: 'CATEGORIA_CRIADA', entity: 'categoria', entityId: rows[0].id, administradoraId: admId, details: { nome: body.nome, tipo: body.tipo } });
      return rows[0];
    });
    return reply.status(201).send(camel(row));
  });

  // O tipo (receita/despesa) não muda depois de criado: já há lançamentos apontando para ele.
  app.patch('/financeiro/categorias/:id', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = z
      .object({ nome: trimmed(120).optional(), grupo: z.enum([...GRUPOS_RECEITA, ...GRUPOS_DESPESA]).optional(), ativo: z.boolean().optional() })
      .strict()
      .parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { sets, values } = buildUpdate(body, { nome: 'nome', grupo: 'grupo', ativo: 'ativo' }, 2);
      const sql = sets.length
        ? `UPDATE categorias_financeiras SET ${sets.join(', ')} WHERE id = $1 RETURNING ${CAT_COLUMNS}`
        : `SELECT ${CAT_COLUMNS} FROM categorias_financeiras WHERE id = $1`;
      const { rows } = await tx.query(sql, [id, ...values]);
      if (!rows[0]) throw notFound('Categoria não encontrada');
      if (sets.length) await audit(tx, req, { action: 'CATEGORIA_ALTERADA', entity: 'categoria', entityId: id, administradoraId: rows[0].administradora_id, details: body });
      return camel(rows[0]);
    });
  });

  // -------------------------------------------------------------------
  // Contas financeiras
  // -------------------------------------------------------------------
  const contaDados = z.object({
    nome: trimmed(120),
    tipo: z.enum(['CAIXA', 'CONTA_CORRENTE', 'POUPANCA', 'APLICACAO']),
    banco: optionalText(100),
    agencia: optionalText(20),
    numero: optionalText(30),
    saldoInicial: zMoney.default('0.00'),
    dataSaldoInicial: zDate.optional(),
  });

  app.get('/financeiro/contas', async (req) => {
    const p = requirePrincipal(req);
    const q = zAdmQuery.extend({ incluirInativas: zQueryBool.default(false) }).parse(req.query);
    const admId = resolveAdministradora(p, q.administradoraId);
    return withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `SELECT ${CONTA_COLUMNS} FROM contas_financeiras WHERE administradora_id = $1 AND ($2 OR ativo) ORDER BY nome`,
        [admId, q.incluirInativas],
      );
      // Colaboradores escolhem a conta ao dar baixa, mas saldos são informação gerencial.
      const showBalance = p.role !== 'ADMIN_COLABORADOR';
      return {
        dados: rows.map((r) => {
          const c = camel(r);
          if (!showBalance) {
            delete c.saldoInicial;
            delete c.dataSaldoInicial;
          }
          return c;
        }),
      };
    });
  });

  app.post('/financeiro/contas', { preHandler: gestao }, async (req, reply) => {
    const p = requirePrincipal(req);
    const body = contaDados.extend({ administradoraId: zUuid.nullish() }).parse(req.body);
    const admId = resolveAdministradora(p, body.administradoraId);
    const row = await withTx(dbContext(p), async (tx) => {
      const { rows } = await tx.query(
        `INSERT INTO contas_financeiras (administradora_id, nome, tipo, banco, agencia, numero, saldo_inicial, data_saldo_inicial, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8::date, current_date), $9) RETURNING ${CONTA_COLUMNS}`,
        [admId, body.nome, body.tipo, body.banco ?? null, body.agencia ?? null, body.numero ?? null, body.saldoInicial, body.dataSaldoInicial ?? null, p.userId],
      );
      await audit(tx, req, { action: 'CONTA_FINANCEIRA_CRIADA', entity: 'conta_financeira', entityId: rows[0].id, administradoraId: admId, details: { nome: body.nome, saldoInicial: body.saldoInicial } });
      return rows[0];
    });
    return reply.status(201).send(camel(row));
  });

  app.patch('/financeiro/contas/:id', { preHandler: gestao }, async (req) => {
    const p = requirePrincipal(req);
    const { id } = zIdParam.parse(req.params);
    const body = contaDados.extend({ ativo: z.boolean() }).partial().strict().parse(req.body);
    return withTx(dbContext(p), async (tx) => {
      const { sets, values } = buildUpdate(
        body,
        { nome: 'nome', tipo: 'tipo', banco: 'banco', agencia: 'agencia', numero: 'numero', saldoInicial: 'saldo_inicial', dataSaldoInicial: 'data_saldo_inicial', ativo: 'ativo' },
        2,
      );
      const sql = sets.length
        ? `UPDATE contas_financeiras SET ${sets.join(', ')} WHERE id = $1 RETURNING ${CONTA_COLUMNS}`
        : `SELECT ${CONTA_COLUMNS} FROM contas_financeiras WHERE id = $1`;
      const { rows } = await tx.query(sql, [id, ...values]);
      if (!rows[0]) throw notFound('Conta não encontrada');
      if (sets.length) await audit(tx, req, { action: 'CONTA_FINANCEIRA_ALTERADA', entity: 'conta_financeira', entityId: id, administradoraId: rows[0].administradora_id, details: body });
      return camel(rows[0]);
    });
  });
}
