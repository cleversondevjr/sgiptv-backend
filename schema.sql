CREATE TABLE IF NOT EXISTS pagamentos (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  telefone TEXT NOT NULL,
  plano TEXT NOT NULL,
  valor NUMERIC(10, 2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendente',
  payment_id TEXT UNIQUE NOT NULL,
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
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS clientes_usuario_idx
  ON clientes (usuario);
