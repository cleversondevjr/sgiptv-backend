CREATE TABLE IF NOT EXISTS pagamentos (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  telefone TEXT NOT NULL,
  plano TEXT NOT NULL,
  valor NUMERIC(10, 2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendente',
  payment_id TEXT UNIQUE NOT NULL,
  cliente_usuario TEXT,
  cliente_senha TEXT,
  confirmado_em TIMESTAMPTZ,
  notificado_em TIMESTAMPTZ,
  cancelado_em TIMESTAMPTZ,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT pagamentos_status_check CHECK (status IN ('pendente', 'confirmado', 'cancelado'))
);

CREATE INDEX IF NOT EXISTS pagamentos_email_telefone_idx
  ON pagamentos (email, telefone);

CREATE INDEX IF NOT EXISTS pagamentos_status_idx
  ON pagamentos (status);

CREATE TABLE IF NOT EXISTS testes_iptv (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  telefone TEXT NOT NULL,
  resposta TEXT NOT NULL,
  login TEXT,
  senha TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS testes_iptv_email_telefone_idx
  ON testes_iptv (email, telefone);

CREATE TABLE IF NOT EXISTS clientes (
  id BIGSERIAL PRIMARY KEY,
  usuario TEXT NOT NULL UNIQUE,
  senha TEXT NOT NULL,
  plano TEXT NOT NULL,
  conexoes INTEGER NOT NULL DEFAULT 1,
  criado_em TIMESTAMPTZ NOT NULL,
  vencimento TIMESTAMPTZ NOT NULL,
  email TEXT,
  telefone TEXT,
  nome TEXT,
  aviso_3d_em TIMESTAMPTZ,
  aviso_1d_em TIMESTAMPTZ,
  revendedor_id BIGINT,
  revendedor_vinculado_em TIMESTAMPTZ,
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS clientes_usuario_idx
  ON clientes (usuario);

CREATE TABLE IF NOT EXISTS revendedores (
  id BIGSERIAL PRIMARY KEY,
  codigo TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  nome_completo TEXT,
  pix_cpf TEXT UNIQUE,
  banco_nome TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS comissoes (
  id BIGSERIAL PRIMARY KEY,
  revendedor_id BIGINT NOT NULL REFERENCES revendedores(id) ON DELETE CASCADE,
  cliente_id BIGINT NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  pagamento_id BIGINT NOT NULL REFERENCES pagamentos(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL,
  valor NUMERIC(10,2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendente',
  transacao_id TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  pago_em TIMESTAMPTZ,
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT comissoes_tipo_check CHECK (tipo IN ('primeira_compra', 'renovacao')),
  CONSTRAINT comissoes_status_check CHECK (status IN ('pendente', 'processando', 'pago', 'falhou'))
);

CREATE INDEX IF NOT EXISTS comissoes_revendedor_status_idx
  ON comissoes (revendedor_id, status);

CREATE INDEX IF NOT EXISTS comissoes_cliente_idx
  ON comissoes (cliente_id);
