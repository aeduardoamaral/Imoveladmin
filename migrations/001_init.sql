-- =====================================================================
-- ImovelAdmin - Camada 1: Master, Administradoras, Usuários, Condomínios
-- =====================================================================
-- Modelo de segurança do banco:
--   * As migrações rodam com o papel DONO (imovel_owner).
--   * A aplicação conecta com um papel SEM privilégios (imovel_app), que
--     não é dono das tabelas e portanto está sujeito a Row-Level Security.
--   * Cada transação da aplicação declara seu contexto via
--     set_config('app.role', ...) e set_config('app.tenant_id', ...).
--     Sem contexto declarado, nenhuma linha é visível (fail-closed).
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------
-- Funções de contexto
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app_role() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.role', true), '')
$$;

CREATE OR REPLACE FUNCTION app_tenant_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

-- 'system' = fluxos de autenticação (login, convite, refresh)
-- 'master' = usuário Master da plataforma
CREATE OR REPLACE FUNCTION app_is_privileged() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT COALESCE(app_role() IN ('master', 'system'), false)
$$;

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------
-- Administradoras
-- ---------------------------------------------------------------------
CREATE TABLE administradoras (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  razao_social   text NOT NULL CHECK (length(razao_social) BETWEEN 2 AND 200),
  nome_fantasia  text CHECK (length(nome_fantasia) <= 200),
  cnpj           char(14) NOT NULL UNIQUE CHECK (cnpj ~ '^[0-9A-Z]{12}[0-9]{2}$'),
  email          citext NOT NULL CHECK (length(email) <= 254),
  telefone       text CHECK (length(telefone) <= 20),
  cep            char(8) CHECK (cep ~ '^[0-9]{8}$'),
  logradouro     text CHECK (length(logradouro) <= 200),
  numero         text CHECK (length(numero) <= 20),
  complemento    text CHECK (length(complemento) <= 100),
  bairro         text CHECK (length(bairro) <= 100),
  cidade         text CHECK (length(cidade) <= 100),
  uf             char(2) CHECK (uf ~ '^[A-Z]{2}$'),
  status         text NOT NULL DEFAULT 'ATIVA' CHECK (status IN ('ATIVA', 'SUSPENSA', 'INATIVA')),
  created_by     uuid,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_administradoras_updated BEFORE UPDATE ON administradoras
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Usuários (Master e colaboradores das administradoras)
-- ---------------------------------------------------------------------
CREATE TABLE users (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  administradora_id   uuid REFERENCES administradoras(id) ON DELETE RESTRICT,
  nome                text NOT NULL CHECK (length(nome) BETWEEN 2 AND 150),
  email               citext NOT NULL UNIQUE CHECK (length(email) <= 254),
  cpf                 char(11) UNIQUE CHECK (cpf ~ '^[0-9]{11}$'),
  telefone            text CHECK (length(telefone) <= 20),
  role                text NOT NULL CHECK (role IN ('MASTER', 'ADMIN_GESTOR', 'ADMIN_COLABORADOR')),
  status              text NOT NULL DEFAULT 'PENDENTE' CHECK (status IN ('PENDENTE', 'ATIVO', 'SUSPENSO')),
  password_hash       text,
  password_changed_at timestamptz,
  mfa_secret_enc      text,
  mfa_enabled         boolean NOT NULL DEFAULT false,
  mfa_last_step       bigint,
  failed_logins       integer NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  last_login_at       timestamptz,
  created_by          uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  -- Master nunca pertence a uma administradora; demais papéis sempre pertencem.
  CONSTRAINT users_role_tenant CHECK (
    (role = 'MASTER' AND administradora_id IS NULL) OR
    (role <> 'MASTER' AND administradora_id IS NOT NULL)
  )
);
CREATE INDEX idx_users_administradora ON users(administradora_id);
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Condomínios
-- ---------------------------------------------------------------------
CREATE TABLE condominios (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  administradora_id   uuid NOT NULL REFERENCES administradoras(id) ON DELETE RESTRICT,
  nome                text NOT NULL CHECK (length(nome) BETWEEN 2 AND 200),
  cnpj                char(14) UNIQUE CHECK (cnpj ~ '^[0-9A-Z]{12}[0-9]{2}$'),
  tipo                text NOT NULL DEFAULT 'RESIDENCIAL' CHECK (tipo IN ('RESIDENCIAL', 'COMERCIAL', 'MISTO')),
  num_unidades        integer CHECK (num_unidades BETWEEN 0 AND 100000),
  num_blocos          integer CHECK (num_blocos BETWEEN 0 AND 1000),
  cep                 char(8) NOT NULL CHECK (cep ~ '^[0-9]{8}$'),
  logradouro          text NOT NULL CHECK (length(logradouro) <= 200),
  numero              text NOT NULL CHECK (length(numero) <= 20),
  complemento         text CHECK (length(complemento) <= 100),
  bairro              text NOT NULL CHECK (length(bairro) <= 100),
  cidade              text NOT NULL CHECK (length(cidade) <= 100),
  uf                  char(2) NOT NULL CHECK (uf ~ '^[A-Z]{2}$'),
  status              text NOT NULL DEFAULT 'ATIVO' CHECK (status IN ('ATIVO', 'INATIVO')),
  created_by          uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_condominios_administradora ON condominios(administradora_id);
CREATE TRIGGER trg_condominios_updated BEFORE UPDATE ON condominios
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Sessões (refresh tokens com rotação e detecção de reuso)
-- ---------------------------------------------------------------------
CREATE TABLE sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id        uuid NOT NULL,
  refresh_hash     char(64) UNIQUE,          -- SHA-256 do refresh token (nunca o token)
  impersonator_id  uuid REFERENCES users(id),
  impersonation_reason text,
  ip               inet,
  user_agent       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  revoked_reason   text
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_family ON sessions(family_id);

-- ---------------------------------------------------------------------
-- Desafios de MFA (login em duas etapas)
-- ---------------------------------------------------------------------
CREATE TABLE auth_challenges (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   char(64) NOT NULL UNIQUE,
  pending_secret_enc text,                   -- segredo TOTP em configuração
  attempts     integer NOT NULL DEFAULT 0,
  ip           inet,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz
);
CREATE INDEX idx_auth_challenges_user ON auth_challenges(user_id);

-- ---------------------------------------------------------------------
-- Convites (definição de senha inicial / redefinição pelo Master)
-- ---------------------------------------------------------------------
CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  char(64) NOT NULL UNIQUE,
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
CREATE INDEX idx_invitations_user ON invitations(user_id);

-- ---------------------------------------------------------------------
-- Trilha de auditoria (append-only, encadeada por hash)
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
  id                 bigint PRIMARY KEY,
  at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_user_id      uuid,
  impersonator_id    uuid,
  administradora_id  uuid,
  action             text NOT NULL,
  entity             text,
  entity_id          text,
  ip                 inet,
  user_agent         text,
  details            jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash          char(64) NOT NULL,
  hash               char(64) NOT NULL
);
CREATE SEQUENCE audit_logs_id_seq OWNED BY audit_logs.id;
CREATE INDEX idx_audit_administradora ON audit_logs(administradora_id, at DESC);
CREATE INDEX idx_audit_actor ON audit_logs(actor_user_id, at DESC);

CREATE OR REPLACE FUNCTION audit_row_payload(r audit_logs) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT concat_ws('|',
    r.id::text,
    to_char(r.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
    COALESCE(r.actor_user_id::text, ''),
    COALESCE(r.impersonator_id::text, ''),
    COALESCE(r.administradora_id::text, ''),
    r.action,
    COALESCE(r.entity, ''),
    COALESCE(r.entity_id, ''),
    COALESCE(host(r.ip), ''),
    COALESCE(r.user_agent, ''),
    r.details::text,
    r.prev_hash)
$$;

-- SECURITY DEFINER: precisa ver a última linha independentemente do RLS.
CREATE OR REPLACE FUNCTION audit_logs_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  last_hash char(64);
BEGIN
  -- Serializa inserções para manter a cadeia íntegra.
  PERFORM pg_advisory_xact_lock(7311001);
  SELECT hash INTO last_hash FROM audit_logs ORDER BY id DESC LIMIT 1;
  NEW.id := nextval('audit_logs_id_seq');
  NEW.at := clock_timestamp();
  NEW.prev_hash := COALESCE(last_hash, repeat('0', 64));
  NEW.hash := encode(sha256(convert_to(audit_row_payload(NEW), 'UTF8')), 'hex');
  RETURN NEW;
END $$;

CREATE TRIGGER trg_audit_chain BEFORE INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_chain();

CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs é somente-inserção (append-only)';
END $$;

CREATE TRIGGER trg_audit_no_update BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();

-- Verificação da cadeia (somente Master pela API)
CREATE OR REPLACE FUNCTION audit_verify_chain()
RETURNS TABLE (total bigint, broken_at bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  r audit_logs;
  expected_prev char(64) := repeat('0', 64);
  n bigint := 0;
BEGIN
  FOR r IN SELECT * FROM audit_logs ORDER BY id LOOP
    n := n + 1;
    IF r.prev_hash <> expected_prev
       OR r.hash <> encode(sha256(convert_to(audit_row_payload(r), 'UTF8')), 'hex') THEN
      total := n; broken_at := r.id; RETURN NEXT; RETURN;
    END IF;
    expected_prev := r.hash;
  END LOOP;
  total := n; broken_at := NULL; RETURN NEXT;
END $$;

-- ---------------------------------------------------------------------
-- Revogação de sessões respeitando o tenant do chamador
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION revoke_user_sessions(p_user uuid, p_reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  n integer;
BEGIN
  IF NOT (app_is_privileged() OR EXISTS (
      SELECT 1 FROM users WHERE id = p_user AND administradora_id = app_tenant_id())) THEN
    RAISE EXCEPTION 'acesso negado' USING ERRCODE = '42501';
  END IF;
  UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
   WHERE (user_id = p_user OR impersonator_id = p_user) AND revoked_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

REVOKE EXECUTE ON FUNCTION revoke_user_sessions(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION audit_verify_chain() FROM PUBLIC;

-- ---------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------
ALTER TABLE administradoras ENABLE ROW LEVEL SECURITY;
ALTER TABLE users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE condominios     ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations     ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs      ENABLE ROW LEVEL SECURITY;

-- Administradoras: privilegiados veem tudo; tenant vê apenas a própria.
CREATE POLICY administradoras_isolation ON administradoras
  USING (app_is_privileged() OR id = app_tenant_id())
  WITH CHECK (app_is_privileged());

-- Usuários: tenant vê/edita apenas usuários da própria administradora
-- e nunca pode criar/alterar para outra administradora ou para MASTER.
CREATE POLICY users_isolation ON users
  USING (app_is_privileged() OR administradora_id = app_tenant_id())
  WITH CHECK (
    app_is_privileged() OR
    (administradora_id = app_tenant_id() AND role <> 'MASTER')
  );

CREATE POLICY condominios_isolation ON condominios
  USING (app_is_privileged() OR administradora_id = app_tenant_id())
  WITH CHECK (app_is_privileged() OR administradora_id = app_tenant_id());

-- Tabelas de autenticação: apenas contexto privilegiado.
CREATE POLICY sessions_priv ON sessions
  USING (app_is_privileged()) WITH CHECK (app_is_privileged());
CREATE POLICY auth_challenges_priv ON auth_challenges
  USING (app_is_privileged()) WITH CHECK (app_is_privileged());
CREATE POLICY invitations_priv ON invitations
  USING (app_is_privileged() OR EXISTS (
    SELECT 1 FROM users u WHERE u.id = invitations.user_id))
  WITH CHECK (app_is_privileged() OR EXISTS (
    SELECT 1 FROM users u WHERE u.id = invitations.user_id
      AND u.administradora_id = app_tenant_id()));

-- Auditoria: qualquer contexto declarado pode inserir; leitura isolada.
CREATE POLICY audit_insert ON audit_logs FOR INSERT
  WITH CHECK (app_role() IS NOT NULL);
CREATE POLICY audit_select ON audit_logs FOR SELECT
  USING (app_role() = 'master' OR administradora_id = app_tenant_id());

-- ---------------------------------------------------------------------
-- Privilégios do papel da aplicação (mínimo necessário)
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_setting('migrate.app_role', true)) THEN
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', current_setting('migrate.app_role'));
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', current_setting('migrate.app_role'));
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON administradoras, users, condominios, sessions, auth_challenges, invitations TO %I', current_setting('migrate.app_role'));
    EXECUTE format('GRANT SELECT, INSERT ON audit_logs TO %I', current_setting('migrate.app_role'));
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_verify_chain() TO %I', current_setting('migrate.app_role'));
    EXECUTE format('GRANT EXECUTE ON FUNCTION revoke_user_sessions(uuid, text) TO %I', current_setting('migrate.app_role'));
  ELSE
    RAISE EXCEPTION 'Papel da aplicação (migrate.app_role) não encontrado';
  END IF;
END $$;
