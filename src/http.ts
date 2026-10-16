import { z } from 'zod';
import { isValidCnpj, isValidCpf, normalizeCnpj, onlyDigits } from './security/documents.js';

const trimmed = (max: number) => z.string().trim().min(1).max(max);
const optionalText = (max: number) =>
  z.string().trim().max(max).transform((v) => (v === '' ? null : v)).nullish();

export const zEmail = z.string().trim().toLowerCase().max(254).email('E-mail inválido');
export const zUuid = z.string().uuid();
export const zCnpj = z
  .string()
  .transform(normalizeCnpj)
  .refine(isValidCnpj, 'CNPJ inválido');
export const zCpf = z
  .string()
  .transform(onlyDigits)
  .refine(isValidCpf, 'CPF inválido');
export const zCep = z
  .string()
  .transform(onlyDigits)
  .refine((v) => v.length === 8, 'CEP inválido');
export const zUf = z
  .string()
  .trim()
  .toUpperCase()
  .refine((v) =>
    ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'].includes(v),
    'UF inválida',
  );
export const zTelefone = z
  .string()
  .transform(onlyDigits)
  .refine((v) => v.length >= 10 && v.length <= 13, 'Telefone inválido');

export { trimmed, optionalText };

export const zPage = z.object({
  pagina: z.coerce.number().int().min(1).max(100000).default(1),
  porPagina: z.coerce.number().int().min(1).max(100).default(20),
});

export const zIdParam = z.object({ id: zUuid });

/** Converte linha snake_case do banco para camelCase da API. */
export function camel<T extends Record<string, unknown>>(row: T): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) out[k.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())] = v;
  return out;
}

/** Monta SET dinâmico para UPDATE a partir de um objeto já validado (colunas fixas por allowlist). */
export function buildUpdate(fields: Record<string, unknown>, columns: Record<string, string>, startIndex = 1) {
  const sets: string[] = [];
  const values: unknown[] = [];
  for (const [key, col] of Object.entries(columns)) {
    if (fields[key] !== undefined) {
      values.push(fields[key]);
      sets.push(`${col} = $${startIndex + values.length - 1}`);
    }
  }
  return { sets, values };
}

/**
 * Valor monetário em reais. Aceita número (1500.5) ou texto ("1500.50").
 * Sempre convertido para texto com 2 casas: nunca fazemos contas com float.
 */
export const zMoney = z
  .union([z.number(), z.string().trim()])
  .transform((v, ctx) => {
    const s = typeof v === 'number' ? (Number.isFinite(v) ? String(v) : '') : v;
    if (!/^\d{1,12}(\.\d{1,2})?$/.test(s)) {
      ctx.addIssue({ code: 'custom', message: 'Valor inválido (use até 2 casas decimais, ex.: 1500.50)' });
      return z.NEVER;
    }
    return Number(s).toFixed(2);
  });

export const zPositiveMoney = zMoney.refine((v) => Number(v) > 0, 'O valor deve ser maior que zero');

/** Data no formato AAAA-MM-DD. */
export const zDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Data inválida (use AAAA-MM-DD)')
  .refine((v) => {
    const d = new Date(`${v}T00:00:00Z`);
    return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(v);
  }, 'Data inválida');

/** Mês no formato AAAA-MM. */
export const zMes = z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/, 'Mês inválido (use AAAA-MM)');

/** Soma meses a uma data AAAA-MM-DD, ajustando para o último dia do mês quando necessário. */
export function addMonths(date: string, months: number): string {
  const [y, m, d] = date.split('-').map(Number) as [number, number, number];
  const target = new Date(Date.UTC(y, m - 1 + months, 1));
  const lastDay = new Date(Date.UTC(target.getUTCFullYear(), target.getUTCMonth() + 1, 0)).getUTCDate();
  target.setUTCDate(Math.min(d, lastDay));
  return target.toISOString().slice(0, 10);
}

/** Booleano vindo da query string ("true"/"false"). */
export const zQueryBool = z.enum(['true', 'false']).transform((v) => v === 'true');

/** Último dia do mês AAAA-MM, como AAAA-MM-DD. */
export function lastDayOfMonth(mes: string): string {
  const [y, m] = mes.split('-').map(Number) as [number, number];
  return new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10);
}

/** Soma dias a uma data AAAA-MM-DD. */
export function addDays(date: string, days: number): string {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10);
}
