# ImovelAdmin

Plataforma para administradoras de imóveis — administração de condomínios, administração de locação ou as duas operações.

- **Camada 1 — Cadastros:** Master da plataforma, administradoras, colaboradores e condomínios.
- **Camada 2 — Financeiro da administradora:** plano de contas, contas bancárias, lançamentos de receitas e despesas (contas a pagar/receber), DRE, fluxo de caixa e painel gerencial.

Os próximos módulos (processos de locação e de condomínio, moradores, síndicos, conselheiros, fornecedores, pasta contábil, RH etc.) serão construídos sobre esta base e alimentarão o financeiro.

## Stack

- Node.js 22 + TypeScript + [Fastify](https://fastify.dev)
- PostgreSQL 16 com **Row-Level Security** (isolamento entre administradoras dentro do banco)
- Argon2id, TOTP (RFC 6238), AES-256-GCM, JWT (HS256)
- Testes com Vitest contra PostgreSQL real

## Hierarquia e permissões

| Papel | Escopo | Pode |
|---|---|---|
| `MASTER` | Toda a plataforma | Cadastrar/editar/suspender administradoras; criar outros Masters; criar usuários e condomínios em qualquer administradora; acesso assistido a qualquer usuário; auditoria; sessões |
| `ADMIN_GESTOR` (proprietário/gerente) | Própria administradora | Cadastrar/editar condomínios; cadastrar, suspender e resetar MFA de colaboradores; plano de contas e contas bancárias; estornar e cancelar lançamentos; DRE, fluxo de caixa, saldos e painel |
| `ADMIN_COLABORADOR` | Própria administradora | Consultar condomínios; lançar receitas e despesas, editar pendentes e dar baixa |

O **tipo de operação** da administradora (`operaCondominios`, `operaLocacao` — ao menos um) é definido pelo Master e liga/desliga os módulos correspondentes.

## Segurança

**Autenticação**
- Não existe cadastro público. O primeiro Master é criado pela linha de comando no servidor; os demais usuários entram por **convite de uso único** (72h, token guardado só como hash, enviado no fragmento `#` da URL para não vazar em logs).
- **MFA obrigatório para todos** (TOTP — Google/Microsoft Authenticator, Authy). O primeiro login força o cadastro do autenticador. Códigos não podem ser reutilizados (anti-replay) e cada desafio aceita no máximo 5 tentativas em 5 minutos.
- Senhas com **Argon2id** (parâmetros OWASP), mínimo de 12 caracteres, bloqueio de termos comuns, do nome e do e-mail.
- **Bloqueio de conta** por 15 minutos após 5 senhas erradas. Mensagem de erro genérica e tempo de resposta igualado para impedir descobrir e-mails cadastrados.
- **Limite de requisições** por IP (10/min nos endpoints de login, MFA e convite; 300/min no geral).

**Sessões**
- Access token de 10 minutos + refresh token opaco em cookie `HttpOnly`, `Secure`, `SameSite=Strict`, restrito a `/auth`.
- **Rotação do refresh token** a cada uso, com **detecção de reuso**: se um token antigo é reapresentado (sinal de roubo), toda a família de sessões é derrubada e o evento é auditado.
- A cada requisição o servidor confere no banco se a sessão, o usuário e a administradora continuam ativos: suspender alguém tem efeito **imediato**.
- Troca de senha, troca de papel, suspensão e reset de MFA encerram as sessões do usuário.

**Isolamento entre administradoras (multi-tenant)**
- A aplicação conecta ao banco com um papel **sem privilégios** (`imovel_app`), que não é dono das tabelas e está sujeito a **Row-Level Security**.
- Cada transação declara seu contexto (`master`, `tenant` + id da administradora, ou `system` para os fluxos de login). **Sem contexto, nenhuma linha é visível** (fail-closed). Mesmo que um bug na API esqueça um filtro, o banco não entrega dados de outra administradora.
- Um gestor não consegue criar nem promover ninguém a `MASTER` — a regra está tanto na API quanto no banco.

**Acesso assistido do Master** (`POST /master/acesso-assistido`)
- Exige motivo, dura no máximo 30 minutos e não é renovável.
- Toda ação registrada traz o usuário-alvo **e** o Master responsável.
- Bloqueado contra outros Masters e para operações pessoais (troca de senha/MFA). Se o Master for suspenso, o acesso assistido cai junto.

**Auditoria**
- Login, falhas, bloqueios, cadastros, alterações, mudanças de status, convites, MFA e acesso assistido ficam na trilha `audit_logs`, gravada **na mesma transação** da operação.
- A tabela é **somente-inserção** (gatilhos impedem UPDATE/DELETE/TRUNCATE, inclusive para o dono) e **encadeada por SHA-256**: qualquer adulteração direta no banco é detectada por `GET /master/auditoria/integridade`.

**Outros**
- Segredos de MFA cifrados com AES-256-GCM, vinculados ao id do usuário.
- Validação estrita de entrada (Zod), incluindo **CPF** e **CNPJ — também o novo CNPJ alfanumérico** da Receita Federal.
- Cabeçalhos de segurança (HSTS, CSP, `no-referrer`, `nosniff`), CORS por lista de origens, proteção CSRF por cabeçalho no refresh, `Cache-Control: no-store`.
- Logs nunca registram senhas, tokens, cookies ou códigos.
- Não há exclusão física de administradoras, usuários ou condomínios — apenas mudança de status, preservando o histórico.

## Financeiro da administradora (Camada 2)

- **Plano de contas**: cada administradora nasce com 21 categorias padrão do setor (taxa de administração de condomínios e de locação, intermediação, impostos, folha, aluguel do escritório, comissões etc.), agrupadas para a DRE. O gestor pode criar, renomear e desativar categorias.
- **Contas financeiras**: caixa, conta corrente, poupança e aplicação, com saldo inicial.
- **Lançamentos**: receita ou despesa, com competência, vencimento, contraparte (cliente/fornecedor), documento (nº da NF/boleto), vínculo opcional com um condomínio (centro de resultado) e repetição mensal (2 a 60 meses). Situação: pendente, atrasado, pago ou cancelado.
- **Regras**: só lançamentos pendentes podem ser editados; pago exige estorno pela gestão antes; cancelamento e estorno exigem motivo e ficam na auditoria (com valores de antes e depois).
- **Relatórios**: DRE gerencial por competência ou por caixa (filtrável por condomínio), fluxo de caixa mensal realizado + previsto com saldo projetado, saldos por conta.
- **Painel**: resultado do mês (competência e caixa), margem, a receber/a pagar (vencidos e próximos 30 dias), saldos, série de 12 meses, despesas por grupo, resultado por condomínio e próximos vencimentos.
- **Valores** são trafegados como texto com 2 casas (`"1500.00"`) e calculados em centavos — sem erro de arredondamento.
- **Integridade**: chaves compostas no banco impedem que um lançamento aponte para categoria, conta ou condomínio de outra administradora, além do RLS.

## Como rodar

```bash
cp .env.example .env              # preencha os segredos (veja os comentários)
export POSTGRES_PASSWORD=... OWNER_DB_PASSWORD=... APP_DB_PASSWORD=...
docker compose up -d db           # PostgreSQL com os papéis owner/app
npm install
npm run migrate                   # aplica o schema (usa DATABASE_OWNER_URL)
npm run master:create -- --email voce@empresa.com.br --nome "Seu Nome"
npm run dev                       # API em http://localhost:3000
```

O `master:create` imprime o link de convite. Use o token (parte após `#`) em `POST /auth/convite/aceitar` para definir a senha; no primeiro login você cadastra o autenticador.

### Testes

```bash
npm run typecheck
npm test     # exige PostgreSQL com o banco imoveladmin_test (veja vitest.config.ts)
```

## API

Todas as rotas (exceto login/MFA/convite/refresh) exigem `Authorization: Bearer <accessToken>`.

**Autenticação**

| Método | Rota | Descrição |
|---|---|---|
| POST | `/auth/login` | `{ email, senha }` → `{ etapa: "MFA" \| "MFA_CADASTRO", desafio }` |
| POST | `/auth/mfa/cadastro` | `{ desafio }` → `{ segredo, otpauthUrl }` (gerar QR Code) |
| POST | `/auth/mfa/verificar` | `{ desafio, codigo }` → `{ accessToken }` + cookie de refresh |
| POST | `/auth/refresh` | Cookie + cabeçalho `X-CSRF-Protection: 1` → novo `accessToken` |
| POST | `/auth/logout` | Encerra a sessão |
| GET | `/auth/me` | Usuário logado |
| POST | `/auth/senha/alterar` | `{ senhaAtual, novaSenha }` |
| POST | `/auth/convite/aceitar` | `{ token, senha }` |

**Administradoras** (Master; `GET /:id` também para a própria administradora)

| Método | Rota | Descrição |
|---|---|---|
| POST | `/administradoras` | Cria administradora + gestor responsável; retorna link de convite |
| GET | `/administradoras` | Lista (`status`, `busca`, `pagina`, `porPagina`) |
| GET | `/administradoras/:id` | Detalhe |
| PATCH | `/administradoras/:id` | Altera dados |
| PATCH | `/administradoras/:id/status` | `{ status: ATIVA\|SUSPENSA\|INATIVA, motivo }` — suspender derruba as sessões |

**Usuários** (Master e Gestor)

| Método | Rota | Descrição |
|---|---|---|
| POST | `/usuarios` | `{ nome, email, cpf?, telefone?, papel, administradoraId? }` — retorna convite |
| GET | `/usuarios` | Lista (`administradoraId` para o Master, `papel`, `status`) |
| GET | `/usuarios/:id` | Detalhe |
| PATCH | `/usuarios/:id` | `{ nome?, telefone?, papel? }` |
| PATCH | `/usuarios/:id/status` | `{ status: ATIVO\|SUSPENSO, motivo }` |
| POST | `/usuarios/:id/convite` | Reemite convite / link de redefinição de senha |
| POST | `/usuarios/:id/mfa/resetar` | `{ motivo }` — usuário cadastra novo autenticador |

**Condomínios** (consulta: todos; escrita: Master e Gestor)

| Método | Rota | Descrição |
|---|---|---|
| POST | `/condominios` | `{ nome, cnpj?, tipo, numUnidades?, numBlocos?, cep, logradouro, numero, complemento?, bairro, cidade, uf, administradoraId? }` (`administradoraId` obrigatório para o Master) |
| GET | `/condominios` | Lista (`administradoraId` para o Master, `status`, `busca`) |
| GET | `/condominios/:id` | Detalhe |
| PATCH | `/condominios/:id` | Altera dados |
| PATCH | `/condominios/:id/status` | `{ status: ATIVO\|INATIVO, motivo }` |

**Master**

| Método | Rota | Descrição |
|---|---|---|
| POST | `/master/acesso-assistido` | `{ usuarioId, motivo }` → token de 30 min agindo como o usuário |
| GET | `/master/auditoria` | Filtros: `administradoraId`, `usuarioId`, `acao`, `de`, `ate` |
| GET | `/master/auditoria/integridade` | Verifica a cadeia de hashes |
| GET | `/master/sessoes` | Sessões ativas (`usuarioId`) |
| POST | `/master/sessoes/:id/revogar` | Derruba uma sessão |

**Financeiro** (o Master informa `administradoraId` em todas as rotas)

| Método | Rota | Quem | Descrição |
|---|---|---|---|
| GET | `/financeiro/categorias` | Todos | Plano de contas (`tipo`, `incluirInativas`) |
| POST / PATCH | `/financeiro/categorias[/:id]` | Gestão | `{ nome, tipo, grupo }` / `{ nome?, grupo?, ativo? }` |
| GET | `/financeiro/contas` | Todos | Contas (saldo inicial só para a gestão) |
| POST / PATCH | `/financeiro/contas[/:id]` | Gestão | `{ nome, tipo, banco?, agencia?, numero?, saldoInicial?, dataSaldoInicial? }` |
| POST | `/financeiro/lancamentos` | Todos | `{ tipo, descricao, categoriaId, valor, dataVencimento, dataCompetencia?, contaId?, condominioId?, contraparte?, documento?, observacoes?, repetirMeses?, pago?: { dataPagamento?, valorPago?, contaId? } }` |
| GET | `/financeiro/lancamentos` | Todos | Filtros: `tipo`, `situacao`, `categoriaId`, `contaId`, `condominioId`, `campoData` + `de`/`ate`, `busca`; retorna totais |
| GET / PATCH | `/financeiro/lancamentos/:id` | Todos | Detalhe / edição (somente pendentes) |
| POST | `/financeiro/lancamentos/:id/baixa` | Todos | `{ dataPagamento?, valorPago?, contaId? }` |
| POST | `/financeiro/lancamentos/:id/estorno` | Gestão | `{ motivo }` |
| POST | `/financeiro/lancamentos/:id/cancelar` | Gestão | `{ motivo, incluirParcelasFuturas? }` |
| GET | `/financeiro/relatorios/dre` | Gestão | `de`, `ate`, `regime=competencia\|caixa`, `condominioId` |
| GET | `/financeiro/relatorios/fluxo-caixa` | Gestão | `deMes`, `ateMes` (AAAA-MM, até 36 meses) |
| GET | `/financeiro/relatorios/saldos` | Gestão | `data` |
| GET | `/financeiro/dashboard` | Gestão | `mes` (AAAA-MM) |

## Recomendações para produção

- Servir somente via HTTPS atrás de um proxy reverso e ajustar `TRUST_PROXY_HOPS`.
- Guardar `JWT_SECRET`, `MFA_ENCRYPTION_KEY` e senhas do banco em um cofre de segredos (AWS Secrets Manager, GCP Secret Manager, Vault).
- Habilitar criptografia em disco e backups criptografados no PostgreSQL; conexão com o banco via TLS.
- Integrar envio de e-mail para os convites (hoje o link é devolvido ao Master/Gestor que cadastrou).
- Com várias instâncias da API, mover o limite de requisições para Redis.

## Estrutura

```
migrations/001_init.sql   Schema, RLS, auditoria encadeada, privilégios
migrations/002_financeiro.sql  Tipo de operação, plano de contas, contas, lançamentos
src/app.ts                Fastify: segurança, CORS, limites, tratamento de erros
src/db.ts                 Pool e transações com contexto de RLS
src/auth/                 Autenticação por requisição, sessões e convites
src/security/             Senhas, TOTP, criptografia, JWT, CPF/CNPJ
src/routes/               auth, administradoras, usuarios, condominios, master
src/routes/financeiro/    cadastros (categorias/contas), lançamentos, relatórios/painel
src/scripts/              migrate, master:create
tests/                    Testes unitários e de integração
```
