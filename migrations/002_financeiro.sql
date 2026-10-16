-- =====================================================================
-- Camada 2: Tipo de operação da administradora + núcleo financeiro
-- (plano de contas, contas financeiras, lançamentos de receitas/despesas)
-- =====================================================================

-- ---------------------------------------------------------------------
-- Tipo de operação: condomínios, locação ou ambos
-- ---------------------------------------------------------------------
ALTER TABLE administradoras
  ADD COLUMN opera_condominios boolean NOT NULL DEFAULT true,
  ADD COLUMN opera_locacao     boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT administradoras_opera_algo CHECK (opera_condominios OR opera_locacao);

-- Permite chaves estrangeiras compostas (administradora_id, id): garantem no
-- banco que um registro só referencia registros da MESMA administradora.
-- (Verificações de FK ignoram o RLS, por isso a regra precisa estar na chave.)
ALTER TABLE condominios ADD CONSTRAINT condominios_adm_id_uk UNIQUE (administradora_id, id);

-- ---------------------------------------------------------------------
-- Plano de contas (categorias de receita e despesa)
-- ---------------------------------------------------------------------
CREATE TABLE categorias_financeiras (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  administradora_id  uuid NOT NULL REFERENCES administradoras(id) ON DELETE RESTRICT,
  nome               text NOT NULL CHECK (length(nome) BETWEEN 2 AND 120),
  tipo               text NOT NULL CHECK (tipo IN ('RECEITA', 'DESPESA')),
  -- Grupo da DRE em que a categoria é totalizada
  grupo              text NOT NULL,
  ativo              boolean NOT NULL DEFAULT true,
  created_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT categorias_grupo_tipo CHECK (
    (tipo = 'RECEITA' AND grupo IN ('RECEITA_OPERACIONAL', 'RECEITA_FINANCEIRA', 'OUTRAS_RECEITAS')) OR
    (tipo = 'DESPESA' AND grupo IN ('DEDUCOES', 'DESPESA_PESSOAL', 'DESPESA_ADMINISTRATIVA',
                                    'DESPESA_COMERCIAL', 'DESPESA_FINANCEIRA', 'OUTRAS_DESPESAS'))
  ),
  CONSTRAINT categorias_nome_uk UNIQUE (administradora_id, tipo, nome),
  CONSTRAINT categorias_adm_id_tipo_uk UNIQUE (administradora_id, id, tipo)
);
CREATE TRIGGER trg_categorias_updated BEFORE UPDATE ON categorias_financeiras
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Contas financeiras (caixa, bancos, aplicações)
-- ---------------------------------------------------------------------
CREATE TABLE contas_financeiras (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  administradora_id   uuid NOT NULL REFERENCES administradoras(id) ON DELETE RESTRICT,
  nome                text NOT NULL CHECK (length(nome) BETWEEN 2 AND 120),
  tipo                text NOT NULL CHECK (tipo IN ('CAIXA', 'CONTA_CORRENTE', 'POUPANCA', 'APLICACAO')),
  banco               text CHECK (length(banco) <= 100),
  agencia             text CHECK (length(agencia) <= 20),
  numero              text CHECK (length(numero) <= 30),
  saldo_inicial       numeric(14,2) NOT NULL DEFAULT 0,
  data_saldo_inicial  date NOT NULL DEFAULT current_date,
  ativo               boolean NOT NULL DEFAULT true,
  created_by          uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT contas_nome_uk UNIQUE (administradora_id, nome),
  CONSTRAINT contas_adm_id_uk UNIQUE (administradora_id, id)
);
CREATE TRIGGER trg_contas_updated BEFORE UPDATE ON contas_financeiras
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Lançamentos (contas a pagar / a receber)
-- ---------------------------------------------------------------------
CREATE TABLE lancamentos (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  administradora_id   uuid NOT NULL REFERENCES administradoras(id) ON DELETE RESTRICT,
  tipo                text NOT NULL CHECK (tipo IN ('RECEITA', 'DESPESA')),
  descricao           text NOT NULL CHECK (length(descricao) BETWEEN 2 AND 200),
  categoria_id        uuid NOT NULL,
  conta_id            uuid,
  condominio_id       uuid,                  -- centro de custo/receita (opcional)
  contraparte         text CHECK (length(contraparte) <= 200),   -- cliente ou fornecedor
  documento           text CHECK (length(documento) <= 60),      -- nº NF, boleto, recibo
  observacoes         text CHECK (length(observacoes) <= 2000),
  valor               numeric(14,2) NOT NULL CHECK (valor > 0),
  data_competencia    date NOT NULL,
  data_vencimento     date NOT NULL,
  status              text NOT NULL DEFAULT 'PENDENTE' CHECK (status IN ('PENDENTE', 'PAGO', 'CANCELADO')),
  data_pagamento      date,
  valor_pago          numeric(14,2) CHECK (valor_pago > 0),
  recorrencia_id      uuid,
  parcela             integer CHECK (parcela >= 1),
  total_parcelas      integer CHECK (total_parcelas >= 1),
  created_by          uuid,
  updated_by          uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  -- Integridade multi-tenant e de tipo garantida pelo banco:
  CONSTRAINT lanc_categoria_fk FOREIGN KEY (administradora_id, categoria_id, tipo)
    REFERENCES categorias_financeiras (administradora_id, id, tipo),
  CONSTRAINT lanc_conta_fk FOREIGN KEY (administradora_id, conta_id)
    REFERENCES contas_financeiras (administradora_id, id),
  CONSTRAINT lanc_condominio_fk FOREIGN KEY (administradora_id, condominio_id)
    REFERENCES condominios (administradora_id, id),
  CONSTRAINT lanc_pago_completo CHECK (
    (status = 'PAGO' AND data_pagamento IS NOT NULL AND valor_pago IS NOT NULL AND conta_id IS NOT NULL) OR
    (status <> 'PAGO' AND data_pagamento IS NULL AND valor_pago IS NULL)
  )
);
CREATE INDEX idx_lanc_adm_venc ON lancamentos (administradora_id, data_vencimento);
CREATE INDEX idx_lanc_adm_comp ON lancamentos (administradora_id, data_competencia);
CREATE INDEX idx_lanc_adm_pag  ON lancamentos (administradora_id, data_pagamento) WHERE status = 'PAGO';
CREATE INDEX idx_lanc_condominio ON lancamentos (condominio_id) WHERE condominio_id IS NOT NULL;
CREATE INDEX idx_lanc_recorrencia ON lancamentos (recorrencia_id) WHERE recorrencia_id IS NOT NULL;
CREATE TRIGGER trg_lancamentos_updated BEFORE UPDATE ON lancamentos
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Plano de contas padrão para administradoras de imóveis
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION seed_plano_contas(p_adm uuid) RETURNS void
LANGUAGE sql AS $$
  INSERT INTO categorias_financeiras (administradora_id, tipo, grupo, nome)
  SELECT p_adm, t.tipo, t.grupo, t.nome FROM (VALUES
    ('RECEITA', 'RECEITA_OPERACIONAL',    'Taxa de administração de condomínios'),
    ('RECEITA', 'RECEITA_OPERACIONAL',    'Taxa de administração de locação'),
    ('RECEITA', 'RECEITA_OPERACIONAL',    'Taxa de intermediação / primeiro aluguel'),
    ('RECEITA', 'RECEITA_OPERACIONAL',    'Vistorias, contratos e serviços avulsos'),
    ('RECEITA', 'RECEITA_FINANCEIRA',     'Rendimentos de aplicações'),
    ('RECEITA', 'RECEITA_FINANCEIRA',     'Juros e multas recebidos'),
    ('RECEITA', 'OUTRAS_RECEITAS',        'Outras receitas'),
    ('DESPESA', 'DEDUCOES',               'Impostos sobre faturamento (Simples, ISS, PIS, COFINS)'),
    ('DESPESA', 'DESPESA_PESSOAL',        'Salários e encargos'),
    ('DESPESA', 'DESPESA_PESSOAL',        'Pró-labore'),
    ('DESPESA', 'DESPESA_PESSOAL',        'Benefícios (VT, VR, plano de saúde)'),
    ('DESPESA', 'DESPESA_ADMINISTRATIVA', 'Aluguel e condomínio do escritório'),
    ('DESPESA', 'DESPESA_ADMINISTRATIVA', 'Energia, água, telefone e internet'),
    ('DESPESA', 'DESPESA_ADMINISTRATIVA', 'Sistemas e software'),
    ('DESPESA', 'DESPESA_ADMINISTRATIVA', 'Contabilidade e jurídico'),
    ('DESPESA', 'DESPESA_ADMINISTRATIVA', 'Material de escritório e limpeza'),
    ('DESPESA', 'DESPESA_COMERCIAL',      'Marketing e anúncios de imóveis'),
    ('DESPESA', 'DESPESA_COMERCIAL',      'Comissões de corretores'),
    ('DESPESA', 'DESPESA_FINANCEIRA',     'Tarifas bancárias'),
    ('DESPESA', 'DESPESA_FINANCEIRA',     'Juros e multas pagos'),
    ('DESPESA', 'OUTRAS_DESPESAS',        'Outras despesas')
  ) AS t(tipo, grupo, nome)
  ON CONFLICT (administradora_id, tipo, nome) DO NOTHING
$$;

-- Administradoras já existentes recebem o plano padrão.
SELECT seed_plano_contas(id) FROM administradoras;

-- ---------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------
ALTER TABLE categorias_financeiras ENABLE ROW LEVEL SECURITY;
ALTER TABLE contas_financeiras     ENABLE ROW LEVEL SECURITY;
ALTER TABLE lancamentos            ENABLE ROW LEVEL SECURITY;

CREATE POLICY categorias_isolation ON categorias_financeiras
  USING (app_is_privileged() OR administradora_id = app_tenant_id())
  WITH CHECK (app_is_privileged() OR administradora_id = app_tenant_id());
CREATE POLICY contas_isolation ON contas_financeiras
  USING (app_is_privileged() OR administradora_id = app_tenant_id())
  WITH CHECK (app_is_privileged() OR administradora_id = app_tenant_id());
CREATE POLICY lancamentos_isolation ON lancamentos
  USING (app_is_privileged() OR administradora_id = app_tenant_id())
  WITH CHECK (app_is_privileged() OR administradora_id = app_tenant_id());

DO $$
BEGIN
  EXECUTE format('GRANT SELECT, INSERT, UPDATE ON categorias_financeiras, contas_financeiras, lancamentos TO %I',
                 current_setting('migrate.app_role'));
  EXECUTE format('GRANT EXECUTE ON FUNCTION seed_plano_contas(uuid) TO %I', current_setting('migrate.app_role'));
END $$;
