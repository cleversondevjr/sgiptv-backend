import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { MercadoPagoConfig, Payment } from "mercadopago";
import { db } from "./db.js";

const app = express();

app.set("trust proxy", 1);
const allowedOrigins = new Set([
  "https://sgiptv.com.br",
  "https://www.sgiptv.com.br",
  "http://localhost:3000",
  "http://localhost:4000",
  "http://127.0.0.1:5500"
]);

if (process.env.FRONTEND_ORIGIN) {
  for (const origin of process.env.FRONTEND_ORIGIN.split(",")) {
    allowedOrigins.add(origin.trim());
  }
}

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origem nao permitida pelo CORS."));
  }
}));
app.use(express.json());

const requiredEnv = [
  "ACCESS_TOKEN",
  "ADMIN_USER",
  "ADMIN_PASS",
  "DATABASE_URL",
  "JWT_SECRET"
];

const missingEnv = requiredEnv.filter(name => !process.env[name]?.trim());

if (missingEnv.length > 0) {
  throw new Error(`Variaveis de ambiente obrigatorias ausentes: ${missingEnv.join(", ")}`);
}

const client = new MercadoPagoConfig({
  accessToken: process.env.ACCESS_TOKEN?.trim()
});

const JWT_SECRET = process.env.JWT_SECRET.trim();

const ADMIN_EMAIL_AVISOS = "suportesgiptv01@gmail.com";
const ADMIN_PANEL_URL = "https://sgiptv.com.br/admin.html";

const PLANOS = {
  mensal_1_tela: {
    id: "mensal_1_tela",
    nome: "Mensal - 1 Tela",
    valor: 30,
    dias: 30
  },
  mensal_2_telas: {
    id: "mensal_2_telas",
    nome: "Mensal - 2 Telas",
    valor: 50,
    dias: 30
  },
  trimestral_1_tela: {
    id: "trimestral_1_tela",
    nome: "Trimestral - 1 Tela",
    valor: 80,
    dias: 90
  },
  trimestral_2_telas: {
    id: "trimestral_2_telas",
    nome: "Trimestral - 2 Telas",
    valor: 140,
    dias: 90
  }
};

const DIAS_PLANO_POR_VALOR = {
  "30": 30,
  "50": 30,
  "80": 90,
  "140": 90
};

const TESTE_DURACAO_HORAS = Number(process.env.TESTE_DURACAO_HORAS || 3);
const PIX_EXPIRACAO_MINUTOS = Number(process.env.PIX_EXPIRACAO_MINUTOS || 15);
const INTERVALO_TESTE_DIAS = Number(process.env.INTERVALO_TESTE_DIAS || 15);
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN?.trim();
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID?.trim();
const TELEGRAM_MAX_UPDATES = Number(process.env.TELEGRAM_MAX_UPDATES || 30);

const TESTADORES_LIBERADOS = [
  {
    email: "suportesgiptv01@gmail.com",
    telefone: "11919628194"
  },
  {
    email: "cleversonleite2014@gmail.com",
    telefone: "11951623333"
  }
];

const PLANO_LEGADO_POR_VALOR = {
  "30": "mensal_1_tela",
  "50": "mensal_2_telas",
  "80": "trimestral_1_tela",
  "140": "trimestral_2_telas"
};

const TESTE_URLS = {
  iptv_com_adulto: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/BV4D3rLaqZ",
  iptv_sem_adulto: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/8241Kg1mxd",
  p2p: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/B0VDVALK3q"
};

function criarRateLimit({ janelaMs, limite, mensagem }) {
  const tentativas = new Map();

  return (req, res, next) => {
    const chave = `${req.ip}:${req.path}`;
    const agora = Date.now();
    const registro = tentativas.get(chave);

    if (!registro || registro.expiraEm <= agora) {
      tentativas.set(chave, { total: 1, expiraEm: agora + janelaMs });
      return next();
    }

    if (registro.total >= limite) {
      return res.status(429).json({ error: mensagem });
    }

    registro.total += 1;
    return next();
  };
}

const limiteLogin = criarRateLimit({
  janelaMs: 15 * 60 * 1000,
  limite: 10,
  mensagem: "Muitas tentativas. Aguarde alguns minutos e tente novamente."
});

const limitePublico = criarRateLimit({
  janelaMs: 10 * 60 * 1000,
  limite: 30,
  mensagem: "Muitas solicitacoes. Aguarde alguns minutos e tente novamente."
});

const limiteStatusPix = criarRateLimit({
  janelaMs: 10 * 60 * 1000,
  limite: 120,
  mensagem: "Muitas consultas de status. Aguarde alguns minutos e tente novamente."
});

const limiteConteudo = criarRateLimit({
  janelaMs: 10 * 60 * 1000,
  limite: 60,
  mensagem: "Muitas consultas de conteudo. Aguarde alguns minutos e tente novamente."
});

function escaparHtml(valor) {
  return String(valor || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function obterPlano(planoId, valorLegado) {
  const id = String(planoId || PLANO_LEGADO_POR_VALOR[String(valorLegado)] || "").trim();
  return PLANOS[id] || null;
}

function adicionarTempo(data, quantidade, unidade) {
  const resultado = new Date(data);

  if (Number.isNaN(resultado.getTime())) return null;

  if (unidade === "dias") {
    resultado.setDate(resultado.getDate() + quantidade);
  }

  if (unidade === "horas") {
    resultado.setHours(resultado.getHours() + quantidade);
  }

  if (unidade === "minutos") {
    resultado.setMinutes(resultado.getMinutes() + quantidade);
  }

  return resultado.toISOString();
}

function adicionarDiasFimDoDia(data, dias) {
  const resultado = new Date(data);

  if (Number.isNaN(resultado.getTime())) return null;

  resultado.setDate(resultado.getDate() + dias);
  resultado.setHours(23, 59, 59, 999);

  return resultado.toISOString();
}

function diasPlano(pagamento) {
  const valor = String(Number(pagamento?.valor || 0));
  const plano = String(pagamento?.plano || "").toLowerCase();

  if (DIAS_PLANO_POR_VALOR[valor]) return DIAS_PLANO_POR_VALOR[valor];
  if (plano.includes("trimestral")) return 90;

  return 30;
}

function enriquecerPagamento(pagamento) {
  const dataBase = pagamento.confirmado_em || pagamento.criado_em;
  const pixExpiraEm = adicionarTempo(pagamento.criado_em, PIX_EXPIRACAO_MINUTOS, "minutos");
  const dataExpiracao =
    pagamento.expira_em ||
    (pagamento.status === "confirmado"
      ? adicionarDiasFimDoDia(dataBase, diasPlano(pagamento))
      : null);

  return {
    ...pagamento,
    dias_plano: diasPlano(pagamento),
    data_expiracao: dataExpiracao,
    pix_expira_em: pixExpiraEm,
    expirado: dataExpiracao ? new Date(dataExpiracao) < new Date() : false
  };
}

function enriquecerTeste(teste) {
  const dataExpiracao =
    teste.expira_em ||
    adicionarTempo(teste.criado_em, TESTE_DURACAO_HORAS, "horas");

  return {
    ...teste,
    duracao_teste_horas: TESTE_DURACAO_HORAS,
    data_expiracao: dataExpiracao,
    expirado: dataExpiracao ? new Date(dataExpiracao) < new Date() : false
  };
}

function podeGerarTesteSemLimite(email, telefone) {
  return TESTADORES_LIBERADOS.some(tester => (
    tester.email === email &&
    tester.telefone === telefone
  ));
}

function formatarDataPtBr(data) {
  return new Date(data).toLocaleString("pt-BR", {
    timeZone: "America/Sao_Paulo"
  });
}

function classificarAtualizacaoConteudo(texto) {
  const conteudo = String(texto || "").toLowerCase();

  if (conteudo.includes("jogo") || conteudo.includes("futebol") || conteudo.includes("rodada")) {
    return "Jogos do dia";
  }

  if (conteudo.includes("canal") || conteudo.includes("canais")) {
    return "Canais";
  }

  if (conteudo.includes("serie") || conteudo.includes("série") || conteudo.includes("temporada")) {
    return "Series";
  }

  if (conteudo.includes("filme") || conteudo.includes("cinema")) {
    return "Filmes";
  }

  return "Atualizacao";
}

function extrairTextoTelegram(update) {
  const mensagem = update.channel_post || update.message || update.edited_channel_post || update.edited_message;

  if (!mensagem) return null;

  const texto = mensagem.text || mensagem.caption;

  if (!texto) return null;

  return {
    id: update.update_id,
    chatId: String(mensagem.chat?.id || ""),
    texto: String(texto).trim(),
    data: mensagem.date ? new Date(mensagem.date * 1000).toISOString() : null
  };
}

async function buscarAtualizacoesTelegram() {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    return {
      configurado: false,
      atualizacoes: []
    };
  }

  const url = new URL(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates`);
  url.searchParams.set("limit", String(TELEGRAM_MAX_UPDATES));
  url.searchParams.set("allowed_updates", JSON.stringify(["message", "channel_post", "edited_message", "edited_channel_post"]));

  const resposta = await fetch(url);
  const dados = await resposta.json();

  if (!resposta.ok || !dados.ok) {
    throw new Error(dados.description || "Erro ao consultar Telegram.");
  }

  const atualizacoes = dados.result
    .map(extrairTextoTelegram)
    .filter(Boolean)
    .filter(item => item.chatId === TELEGRAM_CHAT_ID)
    .slice(-12)
    .reverse()
    .map(item => ({
      id: item.id,
      categoria: classificarAtualizacaoConteudo(item.texto),
      texto: item.texto,
      data: item.data
    }));

  return {
    configurado: true,
    atualizacoes
  };
}

function verificarToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "Token não enviado" });
  }

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function limparTextoPainel(texto) {
  return String(texto || "")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "")
    .replace(/\\t/g, " ")
    .replace(/\\\//g, "/")
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, codigo) => {
      return String.fromCharCode(parseInt(codigo, 16));
    })
    .replace(/Equipe Power/gi, "Equipe SG IPTV")
    .trim();
}

function extrairMensagemPainel(textoBruto) {
  try {
    const json = JSON.parse(textoBruto);

    if (json.reply) return limparTextoPainel(json.reply);
    if (json.message) return limparTextoPainel(json.message);

    if (Array.isArray(json.data) && json.data[0]?.message) {
      return limparTextoPainel(json.data[0].message);
    }

    return limparTextoPainel(textoBruto);
  } catch {
    return limparTextoPainel(textoBruto);
  }
}

function escolherUrlTeste(tipoTeste) {
  if (tipoTeste === "iptv_com_adulto") return TESTE_URLS.iptv_com_adulto;
  if (tipoTeste === "iptv_sem_adulto") return TESTE_URLS.iptv_sem_adulto;
  if (tipoTeste === "p2p") return TESTE_URLS.p2p;

  return TESTE_URLS.iptv_com_adulto;
}

function extrairLoginSenha(texto) {
  const resposta = limparTextoPainel(texto);

  let login = null;
  let senha = null;

  const linhas = resposta
    .split("\n")
    .map(linha => linha.replace(/\*/g, "").trim())
    .filter(Boolean);

  for (const linha of linhas) {
    if (!login) {
      const loginMatch = linha.match(/^(usu[aá]rio|usuario|login|user)\s*:?\s*(.+)$/i);
      if (loginMatch) login = loginMatch[2].trim();
    }

    if (!senha) {
      const senhaMatch = linha.match(/^(senha|password|pass)\s*:?\s*(.+)$/i);
      if (senhaMatch) senha = senhaMatch[2].trim();
    }
  }

  if (!login) {
    const loginUrlMatch = resposta.match(/username=([^&\s\n\r]+)/i);
    if (loginUrlMatch) login = loginUrlMatch[1].trim();
  }

  if (!senha) {
    const senhaUrlMatch = resposta.match(/password=([^&\s\n\r]+)/i);
    if (senhaUrlMatch) senha = senhaUrlMatch[1].trim();
  }

  return {
    login: login || "Não identificado",
    senha: senha || "Não identificada"
  };
}

function criarBotaoPainelAdmin() {
  return `
    <hr style="border-color:#7e22ce; margin:24px 0;">
    <a href="${ADMIN_PANEL_URL}" target="_blank" style="display:inline-block;padding:12px 18px;background:#facc15;color:#000;text-decoration:none;border-radius:8px;font-weight:bold;">
      🔗 Acessar Painel Admin
    </a>
  `;
}

function criarTransporterEmail() {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return null;

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

async function enviarEmailAvisoAdmin({ assunto, html, text }) {
  try {
    const transporter = criarTransporterEmail();

    if (!transporter) {
      console.log("Email admin não enviado: EMAIL_USER ou EMAIL_PASS ausente.");
      return false;
    }

    await transporter.sendMail({
      from: `"SG IPTV" <${process.env.EMAIL_USER}>`,
      to: ADMIN_EMAIL_AVISOS,
      subject: assunto,
      text,
      html
    });

    return true;
  } catch (error) {
    console.error("Erro ao enviar aviso para admin:", error);
    return false;
  }
}

async function buscarPagamentoPorIdentificacao({ paymentId, email, telefone }) {
  const result = await db.query(
    `
    SELECT *
    FROM pagamentos
    WHERE payment_id = $1
    AND email = $2
    AND telefone = $3
    LIMIT 1
    `,
    [String(paymentId), email, telefone]
  );

  return result.rows[0] || null;
}

async function confirmarPagamentoRecebido(pagamento, origem = "webhook") {
  if (!pagamento || pagamento.status === "confirmado") {
    return pagamento;
  }

  const result = await db.query(
    `
    UPDATE pagamentos
    SET status = $1
    WHERE payment_id = $2
    RETURNING *
    `,
    ["confirmado", String(pagamento.payment_id)]
  );

  const confirmado = result.rows[0] || pagamento;

  await enviarEmailAvisoAdmin({
    assunto: "Pix recebido - SG IPTV",
    text: `
Pix recebido

Plano: ${confirmado.plano}
Valor: R$ ${confirmado.valor}
Email: ${confirmado.email}
WhatsApp: ${confirmado.telefone}
Payment ID: ${confirmado.payment_id}
Origem: ${origem}

Painel Admin: ${ADMIN_PANEL_URL}
    `,
    html: `
      <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
        <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #22c55e; border-radius:14px; padding:25px;">
          <h2 style="color:#22c55e;">Pix recebido</h2>
          <p><strong>Plano:</strong> ${escaparHtml(confirmado.plano)}</p>
          <p><strong>Valor:</strong> R$ ${escaparHtml(confirmado.valor)}</p>
          <p><strong>Email:</strong> ${escaparHtml(confirmado.email)}</p>
          <p><strong>WhatsApp:</strong> ${escaparHtml(confirmado.telefone)}</p>
          <p><strong>Payment ID:</strong> ${escaparHtml(confirmado.payment_id)}</p>
          <p><strong>Origem:</strong> ${escaparHtml(origem)}</p>
          ${criarBotaoPainelAdmin()}
        </div>
      </div>
    `
  });

  return confirmado;
}

async function sincronizarPagamentoMercadoPago(pagamento) {
  if (!pagamento || pagamento.status === "confirmado" || pagamento.status === "cancelado") {
    return pagamento;
  }

  const payment = new Payment(client);
  const result = await payment.get({ id: pagamento.payment_id });

  if (result.status === "approved") {
    return confirmarPagamentoRecebido(pagamento, "mercado_pago");
  }

  return pagamento;
}

async function cancelarPagamentosPixExpirados() {
  await db.query(
    `
    UPDATE pagamentos
    SET status = $1
    WHERE status = $2
    AND criado_em <= NOW() - ($3 || ' minutes')::interval
    `,
    ["cancelado", "pendente", PIX_EXPIRACAO_MINUTOS]
  );
}

app.post("/login", limiteLogin, (req, res) => {
  const { usuario, senha } = req.body;

  if (usuario === process.env.ADMIN_USER && senha === process.env.ADMIN_PASS) {
    const token = jwt.sign({ usuario }, JWT_SECRET, { expiresIn: "1d" });
    return res.json({ token });
  }

  res.status(401).json({ error: "Usuário ou senha inválidos" });
});

db.query("SELECT NOW()")
  .then(res => console.log("Banco conectado:", res.rows))
  .catch(err => console.error("Erro no banco:", err));

app.get("/", (req, res) => {
  res.send("Backend funcionando 🚀");
});

app.get("/conteudo/atualizacoes", limiteConteudo, async (req, res) => {
  try {
    const resultado = await buscarAtualizacoesTelegram();

    res.json({
      ok: true,
      ...resultado
    });
  } catch (error) {
    console.error("Erro ao buscar atualizacoes do Telegram:", error);
    res.status(500).json({ error: "Erro ao buscar atualizacoes de conteudo." });
  }
});

app.post("/pix", limitePublico, async (req, res) => {
  let { planoId, valor, email, telefone } = req.body;
  const planoSelecionado = obterPlano(planoId, valor);

  if (!planoSelecionado || !email || !telefone) {
    return res.status(400).json({ error: "Informe plano, valor, email e WhatsApp." });
  }

  email = String(email).trim().toLowerCase();
  telefone = String(telefone).replace(/\D/g, "");
  const plano = planoSelecionado.nome;
  valor = planoSelecionado.valor;

  try {
    const payment = new Payment(client);

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano,
        payment_method_id: "pix",
        payer: { email },
        date_of_expiration: adicionarTempo(new Date(), PIX_EXPIRACAO_MINUTOS, "minutos"),
        notification_url: "https://sgiptv-backend.onrender.com/webhook"
      }
    });

    const paymentId = String(result.id);

    await db.query(
      `
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [email, telefone, plano, valor, "pendente", paymentId]
    );

    const data = result.point_of_interaction.transaction_data;

    await enviarEmailAvisoAdmin({
      assunto: "Novo Pix gerado - SG IPTV",
      text: `
Novo Pix gerado

Plano: ${plano}
Valor: R$ ${valor}
Email: ${email}
WhatsApp: ${telefone}
Status: pendente
Payment ID: ${paymentId}

Painel Admin: ${ADMIN_PANEL_URL}
      `,
      html: `
        <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
          <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
            <h2 style="color:#facc15;">Novo Pix gerado</h2>
            <p><strong>Plano:</strong> ${escaparHtml(plano)}</p>
            <p><strong>Valor:</strong> R$ ${escaparHtml(valor)}</p>
            <p><strong>Email:</strong> ${escaparHtml(email)}</p>
            <p><strong>WhatsApp:</strong> ${escaparHtml(telefone)}</p>
            <p><strong>Status:</strong> pendente</p>
            <p><strong>Payment ID:</strong> ${paymentId}</p>
            <hr style="border-color:#7e22ce;">
            <p style="color:#facc15;">O cliente gerou um QR Code Pix. Aguarde o pagamento ou acompanhe pelo painel admin.</p>
            ${criarBotaoPainelAdmin()}
          </div>
        </div>
      `
    });

    res.json({
      qr_code: data.qr_code,
      qr_base64: data.qr_code_base64,
      payment_id: paymentId
    });

  } catch (error) {
    console.error("Erro PIX:", error);
    res.status(500).json({ error: "Erro ao gerar Pix" });
  }
});

app.post("/pix/status", limiteStatusPix, async (req, res) => {
  let { payment_id: paymentId, email, telefone } = req.body;

  if (!paymentId || !email || !telefone) {
    return res.status(400).json({ error: "Informe payment_id, email e WhatsApp." });
  }

  email = String(email).trim().toLowerCase();
  telefone = String(telefone).replace(/\D/g, "");
  paymentId = String(paymentId).trim();

  try {
    await cancelarPagamentosPixExpirados();

    let pagamento = await buscarPagamentoPorIdentificacao({ paymentId, email, telefone });

    if (!pagamento) {
      return res.status(404).json({ error: "Pagamento nao encontrado." });
    }

    pagamento = await sincronizarPagamentoMercadoPago(pagamento);

    return res.json({
      ok: true,
      pagamento: enriquecerPagamento(pagamento)
    });

  } catch (error) {
    console.error("Erro ao consultar status Pix:", error);
    return res.status(500).json({ error: "Erro ao consultar status do Pix." });
  }
});

app.get("/pagamentos", verificarToken, async (req, res) => {
  try {
    await cancelarPagamentosPixExpirados();

    const result = await db.query("SELECT * FROM pagamentos ORDER BY id DESC");
    res.json(result.rows.map(enriquecerPagamento));
  } catch (error) {
    console.error("Erro ao buscar pagamentos:", error);
    res.status(500).json({ error: "Erro ao buscar pagamentos" });
  }
});

app.put("/pagamentos/:id/confirmar", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      "UPDATE pagamentos SET status = $1 WHERE id = $2",
      ["confirmado", id]
    );

    res.json({ ok: true, message: "Pagamento confirmado" });
  } catch (error) {
    console.error("Erro ao confirmar pagamento:", error);
    res.status(500).json({ error: "Erro ao confirmar pagamento" });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    const paymentId = req.body?.data?.id;

    if (!paymentId) return res.sendStatus(200);

    const payment = new Payment(client);
    const result = await payment.get({ id: paymentId });

    if (result.status === "approved") {
      await db.query(
        "UPDATE pagamentos SET status = $1 WHERE payment_id = $2",
        ["confirmado", String(paymentId)]
      );

      console.log("✅ Pagamento confirmado automaticamente");
    }

    res.sendStatus(200);

  } catch (error) {
    console.error("Erro webhook:", error);
    res.sendStatus(500);
  }
});

app.post("/cliente/consulta", limitePublico, async (req, res) => {
  let { email, telefone } = req.body;

  if (!email || !telefone) {
    return res.status(400).json({ error: "Informe email e WhatsApp." });
  }

  email = String(email).trim().toLowerCase();
  telefone = String(telefone).replace(/\D/g, "");

  try {
    const pagamentoResult = await db.query(
      `
      SELECT *
      FROM pagamentos
      WHERE email = $1
      AND telefone = $2
      ORDER BY criado_em DESC, id DESC
      LIMIT 1
      `,
      [email, telefone]
    );

    if (pagamentoResult.rows.length > 0) {
      return res.json({
        ok: true,
        cliente: {
          tipoCliente: "pagamento",
          email,
          telefone,
          loginAreaCliente: email,
          senhaAreaCliente: telefone,
          ultimoPagamento: enriquecerPagamento(pagamentoResult.rows[0]),
          ultimoTeste: null
        }
      });
    }

    const testeResult = await db.query(
      `
      SELECT *
      FROM testes_iptv
      WHERE email = $1
      AND telefone = $2
      ORDER BY id DESC
      LIMIT 1
      `,
      [email, telefone]
    );

    if (testeResult.rows.length === 0) {
      return res.status(404).json({
        error: "Nenhum plano ou teste encontrado para este email e WhatsApp."
      });
    }

    const teste = enriquecerTeste(testeResult.rows[0]);
    const dadosTeste = extrairLoginSenha(teste.resposta);

    return res.json({
      ok: true,
      cliente: {
        tipoCliente: "teste",
        email,
        telefone,
        loginAreaCliente: email,
        senhaAreaCliente: telefone,
        ultimoPagamento: null,
        ultimoTeste: {
          ...teste,
          login: dadosTeste.login,
          senha: dadosTeste.senha
        }
      }
    });

  } catch (error) {
    console.error("Erro ao consultar cliente:", error);
    res.status(500).json({ error: "Erro ao consultar área do cliente." });
  }
});

app.post("/teste-iptv", limitePublico, async (req, res) => {
  let { email, telefone, tipoTeste } = req.body;

  if (!email || !telefone) {
    return res.status(400).json({ error: "Informe email e WhatsApp para gerar o teste." });
  }

  email = String(email).trim().toLowerCase();
  telefone = String(telefone).replace(/\D/g, "");
  tipoTeste = tipoTeste || "iptv_com_adulto";

  const liberadoParaTeste = podeGerarTesteSemLimite(email, telefone);

  try {
    if (!liberadoParaTeste) {
      const ultimoTesteResult = await db.query(
        `
        SELECT criado_em
        FROM testes_iptv
        WHERE email = $1 OR telefone = $2
        ORDER BY criado_em DESC, id DESC
        LIMIT 1
        `,
        [email, telefone]
      );

      if (ultimoTesteResult.rows.length > 0) {
        const ultimoTeste = new Date(ultimoTesteResult.rows[0].criado_em);
        const proximoTeste = new Date(ultimoTeste);
        proximoTeste.setDate(proximoTeste.getDate() + INTERVALO_TESTE_DIAS);

        if (proximoTeste > new Date()) {
          return res.status(409).json({
            error: `Este email ou WhatsApp ja solicitou um teste gratis. Tente novamente em ${formatarDataPtBr(proximoTeste)}.`
          });
        }
      }
    }

    if (false && !liberadoParaTeste) {
      const jaExiste = await db.query(
        "SELECT * FROM testes_iptv WHERE email = $1 OR telefone = $2",
        [email, telefone]
      );

      if (jaExiste.rows.length > 0) {
        return res.status(409).json({
          error: "Este email ou WhatsApp já solicitou um teste grátis."
        });
      }
    }

    const urlTeste = escolherUrlTeste(tipoTeste);

    const respostaApi = await fetch(urlTeste, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, telefone })
    });

    const textoBruto = await respostaApi.text();

    if (!respostaApi.ok) {
      console.error("Erro API IPTV:", textoBruto);
      return res.status(500).json({
        error: "O painel IPTV não conseguiu gerar o teste agora."
      });
    }

    const textoFormatado = extrairMensagemPainel(textoBruto);
    const dadosTeste = extrairLoginSenha(textoFormatado);

    await db.query(
      `
      INSERT INTO testes_iptv (email, telefone, resposta)
      VALUES ($1, $2, $3)
      `,
      [email, telefone, textoFormatado]
    );

    let emailEnviado = false;

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        const transporter = criarTransporterEmail();

        await transporter.sendMail({
          from: `"SG IPTV" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: "Seu teste grátis SG IPTV",
          text: textoFormatado,
          html: `
            <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
              <div style="max-width:760px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
                <h2 style="color:#facc15; margin-top:0;">Seu teste grátis SG IPTV foi gerado!</h2>
                <pre style="white-space:pre-wrap;word-wrap:break-word;background:#020617;color:#ffffff;border:1px solid #7e22ce;border-radius:12px;padding:18px;font-size:14px;line-height:1.6;">${escaparHtml(textoFormatado)}</pre>
                <p style="color:#facc15; font-weight:bold;">Equipe SG IPTV</p>
              </div>
            </div>
          `
        });

        emailEnviado = true;

      } catch (emailError) {
        console.error("Erro ao enviar email para cliente, mas teste foi gerado:", emailError);
      }
    }

    await enviarEmailAvisoAdmin({
      assunto: "Novo teste IPTV gerado - SG IPTV",
      text: `
Novo teste IPTV gerado

Tipo de teste: ${tipoTeste}
Email do cliente: ${email}
WhatsApp do cliente: ${telefone}

Login: ${dadosTeste.login}
Senha: ${dadosTeste.senha}

Painel Admin: ${ADMIN_PANEL_URL}
      `,
      html: `
        <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
          <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
            <h2 style="color:#facc15;">Novo teste IPTV gerado</h2>
            <p><strong>Tipo de teste:</strong> ${escaparHtml(tipoTeste)}</p>
            <p><strong>Email do cliente:</strong> ${escaparHtml(email)}</p>
            <p><strong>WhatsApp do cliente:</strong> ${escaparHtml(telefone)}</p>
            <div style="background:#020617; border:1px solid #7e22ce; border-radius:12px; padding:15px; margin-top:15px;">
              <p><strong style="color:#facc15;">Login:</strong> ${escaparHtml(dadosTeste.login)}</p>
              <p><strong style="color:#facc15;">Senha:</strong> ${escaparHtml(dadosTeste.senha)}</p>
            </div>
            <p style="margin-top:18px; color:#facc15;">Resumo completo salvo no banco.</p>
            ${criarBotaoPainelAdmin()}
          </div>
        </div>
      `
    });

    res.json({
      ok: true,
      message: emailEnviado
        ? "Teste gerado e enviado para seu email."
        : "Teste gerado. As configurações aparecerão na tela.",
      resposta: textoFormatado,
      emailEnviado
    });

  } catch (error) {
    console.error("Erro ao gerar teste IPTV:", error);
    res.status(500).json({ error: "Erro ao gerar teste IPTV." });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log("🚀 Backend rodando na porta", PORT);
});

app.get("/testes-iptv", verificarToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT * FROM testes_iptv
      ORDER BY id DESC
    `);

    const lista = result.rows.map(t => {
      const teste = enriquecerTeste(t);
      const dados = extrairLoginSenha(teste.resposta);

      return {
        ...teste,
        login: dados.login,
        senha: dados.senha
      };
    });

    res.json(lista);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar testes" });
  }
});

app.put("/pagamentos/:id/cancelar", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `
      UPDATE pagamentos
      SET status = $1
      WHERE id = $2
      AND status = $3
      RETURNING *
      `,
      ["cancelado", id, "pendente"]
    );

    if (result.rows.length === 0) {
      return res.status(409).json({
        error: "Pagamento nao encontrado ou ja confirmado/cancelado."
      });
    }

    res.json({
      ok: true,
      message: "Pagamento cancelado",
      pagamento: enriquecerPagamento(result.rows[0])
    });
  } catch (error) {
    console.error("Erro ao cancelar pagamento:", error);
    res.status(500).json({ error: "Erro ao cancelar pagamento" });
  }
});
