import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import { loadConfig } from './config.js';
import { HttpError } from './errors.js';
import { administradoraRoutes } from './routes/administradoras.js';
import { authRoutes } from './routes/auth.js';
import { condominioRoutes } from './routes/condominios.js';
import { financeiroCadastrosRoutes } from './routes/financeiro/cadastros.js';
import { financeiroLancamentosRoutes } from './routes/financeiro/lancamentos.js';
import { financeiroRelatoriosRoutes } from './routes/financeiro/relatorios.js';
import { masterRoutes } from './routes/master.js';
import { usuarioRoutes } from './routes/usuarios.js';

export async function buildApp(opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const config = loadConfig();
  const app = Fastify({
    // Confia apenas no número configurado de proxies reversos (evita spoofing de X-Forwarded-For).
    trustProxy: (_addr: string, hop: number) => hop < config.TRUST_PROXY_HOPS,
    bodyLimit: 256 * 1024,
    logger: opts.logger === false ? false : {
      level: config.isProd ? 'info' : 'debug',
      // Nunca registrar credenciais, tokens ou senhas.
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'res.headers["set-cookie"]',
          '*.senha', '*.senhaAtual', '*.novaSenha', '*.token', '*.desafio', '*.codigo', '*.accessToken',
        ],
        censor: '[REDACTED]',
      },
    },
  });

  await app.register(helmet, {
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-site' },
  });
  await app.register(cors, {
    origin: (origin, cb) => cb(null, !origin || config.corsOrigins.includes(origin)),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Protection'],
    maxAge: 600,
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({ statusCode: 429, erro: 'MUITAS_REQUISICOES', mensagem: 'Muitas requisições. Aguarde e tente novamente.' }),
  });

  app.addHook('onSend', async (_req, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) {
      return reply.status(400).send({
        erro: 'VALIDACAO',
        mensagem: 'Dados inválidos',
        campos: err.issues.map((i) => ({ campo: i.path.join('.'), mensagem: i.message })),
      });
    }
    if (err instanceof HttpError) {
      return reply.status(err.statusCode).send({ erro: err.code, mensagem: err.message, detalhes: err.details });
    }
    const pgCode = (err as { code?: string }).code;
    if (pgCode === '23505') return reply.status(409).send({ erro: 'CONFLITO', mensagem: 'Registro já existe (CNPJ, CPF ou e-mail duplicado)' });
    if (pgCode === '23503') return reply.status(400).send({ erro: 'REFERENCIA_INVALIDA', mensagem: 'Categoria, conta ou condomínio inválido para esta administradora' });
    if (pgCode === '42501') return reply.status(403).send({ erro: 'ACESSO_NEGADO', mensagem: 'Acesso negado' });
    if (pgCode === '23514' || pgCode === '22P02') return reply.status(400).send({ erro: 'REQUISICAO_INVALIDA', mensagem: 'Dados inválidos' });
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status >= 400 && status < 500) {
      return reply.status(status).send({ erro: 'REQUISICAO_INVALIDA', mensagem: status === 429 ? 'Muitas requisições' : 'Requisição inválida' });
    }
    req.log.error({ err }, 'erro interno');
    return reply.status(500).send({ erro: 'ERRO_INTERNO', mensagem: 'Erro interno' });
  });

  app.get('/health', { config: { rateLimit: false } }, async () => ({ ok: true }));

  await app.register(authRoutes);
  await app.register(administradoraRoutes);
  await app.register(usuarioRoutes);
  await app.register(condominioRoutes);
  await app.register(masterRoutes);
  await app.register(financeiroCadastrosRoutes);
  await app.register(financeiroLancamentosRoutes);
  await app.register(financeiroRelatoriosRoutes);

  return app;
}
