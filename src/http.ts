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
