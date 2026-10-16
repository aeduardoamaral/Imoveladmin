import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().min(1),
  DATABASE_OWNER_URL: z.string().optional(),
  APP_DB_ROLE: z.string().regex(/^[a-z_][a-z0-9_]*$/).default('imovel_app'),
  JWT_SECRET: z.string().min(48, 'JWT_SECRET deve ter pelo menos 48 caracteres'),
  MFA_ENCRYPTION_KEY: z
    .string()
    .refine((v) => Buffer.from(v, 'base64').length === 32, 'MFA_ENCRYPTION_KEY deve ter 32 bytes em base64'),
  CORS_ORIGINS: z.string().default(''),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(10).default(0),
  APP_PUBLIC_URL: z.string().url().default('http://localhost:5173'),
});

export type Config = z.infer<typeof schema> & { corsOrigins: string[]; isProd: boolean };

let cached: Config | undefined;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  if (cached) return cached;
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Configuração inválida:\n${msg}`);
  }
  const c = parsed.data;
  cached = {
    ...c,
    corsOrigins: c.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    isProd: c.NODE_ENV === 'production',
  };
  return cached;
}
