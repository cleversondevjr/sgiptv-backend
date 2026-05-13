import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "node:crypto";
import nodemailer from "nodemailer";
import helmet from "helmet";
import { MercadoPagoConfig, Payment } from "mercadopago";
import { db } from "./db.js";

const app = express();

app.set("trust proxy", 1);
app.use(helmet());
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
  "DATABASE_URL",
  "JWT_SECRET"
];

const missingEnv = requiredEnv.filter(name => !process.env[name]?.trim());

if (missingEnv.length > 0) {
  throw new Error(`Variaveis de ambiente obrigatorias ausentes: ${missingEnv.join(", ")}`);
}

if (!process.env.ADMIN_PASS?.trim() && !process.env.ADMIN_PASS_HASH?.trim()) {
  throw new Error("Defina ADMIN_PASS ou ADMIN_PASS_HASH.");
}

const client = new MercadoPagoConfig({
  accessToken: process.env.ACCESS_TOKEN?.trim()
});

const JWT_SECRET = process.env.JWT_SECRET.trim();
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET?.trim() || "";
const NOTIFICATION_URL =
  process.env.WEBHOOK_NOTIFICATION_URL?.trim() ||
  "https://api.sgiptv.com.br/webhook";

const PIX_SYNC_INTERVAL_MS = Number(process.env.PIX_SYNC_INTERVAL_MS || 60_000);

const ADMIN_EMAIL_AVISOS = "suportesgiptv01@gmail.com";
const ADMIN_WHATSAPP_AVISOS = "5511919628194";
const ADMIN_PANEL_URL = "https://sgiptv.com.br/admin.html";
const ADMIN_EMAIL_VENCIMENTOS = "suportesgiptv01@gmail.com";
const TELEGRAM_TIMEOUT_MS = Number(process.env.TELEGRAM_TIMEOUT_MS || 8000);

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

async function limparTestesIptvAntigos() {
  // Mantemos o registro do teste por 24h para auditoria, depois limpa.
  // Nao apaga o cliente (tabela clientes), apenas a tabela de testes.
  try {
    await db.query(`DELETE FROM testes_iptv WHERE criado_em <= NOW() - interval '24 hours'`);
  } catch (error) {
    console.error("Erro ao limpar testes IPTV antigos:", error);
  }
}

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

function escaparHtml(valor) {
  return String(valor || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function emailValido(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || ""));
}

function telefoneValido(telefone) {
  const numero = String(telefone || "").replace(/\D/g, "");
  return numero.length >= 10 && numero.length <= 13;
}

function normalizarContato({ email, telefone }) {
  return {
    email: String(email || "").trim().toLowerCase(),
    telefone: String(telefone || "").replace(/\D/g, "")
  };
}

function validarContato({ email, telefone }) {
  if (!emailValido(email)) {
    return "Informe um email valido.";
  }

  if (!telefoneValido(telefone)) {
    return "Informe um WhatsApp valido com DDD.";
  }

  return null;
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
  const emailNormalizado = String(email || "").trim().toLowerCase();
  const telefoneNormalizado = String(telefone || "").replace(/\D/g, "");

  return TESTADORES_LIBERADOS.some(tester => (
    tester.email === emailNormalizado || tester.telefone === telefoneNormalizado
  ));
}

function formatarDataPtBr(data) {
  return new Date(data).toLocaleString("pt-BR", {
    timeZone: "America/Sao_Paulo"
  });
}

function verificarToken(req, res, next) {
  const authorization = String(req.headers.authorization || "").trim();
  const token = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : authorization;

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

function webhookSecretValido(req) {
  if (!WEBHOOK_SECRET) return true;

  const recebido =
    String(req.query.secret || req.headers["x-webhook-secret"] || "").trim();

  if (!recebido) return false;

  const segredoEsperado = Buffer.from(WEBHOOK_SECRET, "utf8");
  const segredoRecebido = Buffer.from(recebido, "utf8");

  if (segredoEsperado.length !== segredoRecebido.length) {
    return false;
  }

  return crypto.timingSafeEqual(segredoEsperado, segredoRecebido);
}

async function adminCredenciaisValidas(usuario, senha) {
  const usuarioEsperado = String(process.env.ADMIN_USER || "").trim();
  const usuarioInformado = String(usuario || "").trim();
  const senhaInformada = String(senha || "").trim();

  if (!usuarioEsperado || usuarioInformado !== usuarioEsperado) return false;

  const senhaHash = process.env.ADMIN_PASS_HASH?.trim();
  const senhaTexto = String(process.env.ADMIN_PASS || "").trim();

  if (senhaHash) {
    try {
      const hashValido = await bcrypt.compare(senhaInformada, senhaHash);
      if (hashValido) return true;
    } catch (error) {
      console.error("ADMIN_PASS_HASH invalido:", error);
    }
  }

  if (senhaTexto) {
    return senhaInformada === senhaTexto;
  }

  return false;
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
  const brevoKey = String(process.env.BREVO_API_KEY || "").trim();
  if (brevoKey) {
    // Fallback via HTTP (porta 443), evita timeout de SMTP em alguns hosts.
    return {
      async sendMail({ from, to, subject, text, html }) {
        const baseFrom = String(from || process.env.EMAIL_FROM || "").trim();
        const fromEmail = extrairEmailFrom(baseFrom) || null;
        const fromName =
          extrairNomeFrom(baseFrom) ||
          String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();

        if (!fromEmail) {
          throw new Error("EMAIL_FROM (ou from) nao configurado para envio via Brevo API.");
        }

        const payload = {
          sender: { email: fromEmail, name: fromName },
          to: String(to || "")
            .split(",")
            .map(v => v.trim())
            .filter(Boolean)
            .map(email => ({ email })),
          subject,
          textContent: text || undefined,
          htmlContent: html || undefined
        };

        const res = await fetch("https://api.brevo.com/v3/smtp/email", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "api-key": brevoKey
          },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          const body = await res.text();
          throw new Error(`Brevo API erro (${res.status}): ${body}`);
        }

        return true;
      }
    };
  }

  const smtpHost = String(process.env.SMTP_HOST || "").trim();
  const smtpUser = String(process.env.SMTP_USER || "").trim();
  const smtpPass = String(process.env.SMTP_PASS || "").trim();

  if (smtpHost && smtpUser && smtpPass) {
    const port = Number(process.env.SMTP_PORT || 587);
    const secure = String(process.env.SMTP_SECURE || "false").trim().toLowerCase() === "true";

    return nodemailer.createTransport({
      host: smtpHost,
      port,
      secure,
      auth: {
        user: smtpUser,
        pass: smtpPass
      }
    });
  }

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return null;

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

function extrairEmailFrom(from) {
  const texto = String(from || "").trim();
  const match = texto.match(/<([^>]+)>/);
  if (match) return match[1].trim();
  if (texto.includes("@")) return texto.replace(/"/g, "").trim();
  return "";
}

function extrairNomeFrom(from) {
  const texto = String(from || "").trim();
  const match = texto.match(/^\"?([^<\"]+?)\"?\s*<[^>]+>$/);
  if (match) return match[1].trim();
  return "";
}

async function enviarEmailAvisoAdmin({ assunto, html, text }) {
  try {
    const transporter = criarTransporterEmail();

    if (!transporter) {
      console.log("Email admin nao enviado: configure SMTP_HOST/SMTP_USER/SMTP_PASS ou EMAIL_USER/EMAIL_PASS.");
      return false;
    }

    // EMAIL_FROM pode vir como: "Nome <email@dominio>" ou apenas "email@dominio".
    // Evita montar strings invalidas do tipo: "\"Nome\" <Nome <email>>" (isso quebra a Brevo).
    const baseFrom = String(process.env.EMAIL_FROM || "").trim();
    const fromEmail =
      extrairEmailFrom(baseFrom) ||
      String(process.env.SMTP_USER || process.env.EMAIL_USER || "").trim();
    const fromName =
      extrairNomeFrom(baseFrom) ||
      String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();
    const from = fromEmail ? `"${fromName}" <${fromEmail}>` : undefined;

    await transporter.sendMail({
      ...(from ? { from } : {}),
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

async function enviarWhatsappAvisoAdmin(texto) {
  const phone = String(process.env.ADMIN_WHATSAPP_NUMBER || ADMIN_WHATSAPP_AVISOS).replace(/\D/g, "");
  const apikey = String(process.env.ADMIN_WHATSAPP_APIKEY || "").trim();

  if (!apikey) {
    console.log("WhatsApp admin nao enviado: ADMIN_WHATSAPP_APIKEY ausente.");
    return false;
  }

  try {
    const url =
      `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}` +
      `&text=${encodeURIComponent(texto)}` +
      `&apikey=${encodeURIComponent(apikey)}`;

    const res = await fetch(url);
    if (!res.ok) {
      console.error("Erro ao enviar WhatsApp admin:", await res.text());
      return false;
    }

    return true;
  } catch (error) {
    console.error("Erro ao enviar WhatsApp admin:", error);
    return false;
  }
}

function obterChatIdTelegram(tipo) {
  const base = String(process.env.TELEGRAM_CHAT_ID || "").trim();
  const especifico = String(
    (tipo === "pix" && process.env.TELEGRAM_CHAT_ID_PIX) ||
    (tipo === "cliente" && process.env.TELEGRAM_CHAT_ID_CLIENTE) ||
    (tipo === "revendedor" && process.env.TELEGRAM_CHAT_ID_REVENDEDOR) ||
    (tipo === "vencimento_1d" && process.env.TELEGRAM_CHAT_ID_VENCIMENTO_1D) ||
    (tipo === "vencimento_3d" && process.env.TELEGRAM_CHAT_ID_VENCIMENTO_3D) ||
    ""
  ).trim();

  return especifico || base;
}

async function enviarEmailPara(destinatario, { assunto, html, text }) {
  try {
    const to = String(destinatario || "").trim();
    if (!to) return false;

    const transporter = criarTransporterEmail();
    if (!transporter) return false;

    const baseFrom = String(process.env.EMAIL_FROM || "").trim();
    const fromEmail =
      extrairEmailFrom(baseFrom) ||
      String(process.env.SMTP_USER || process.env.EMAIL_USER || "").trim();
    const fromName =
      extrairNomeFrom(baseFrom) ||
      String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();
    const from = fromEmail ? `"${fromName}" <${fromEmail}>` : undefined;

    await transporter.sendMail({
      ...(from ? { from } : {}),
      to,
      subject: assunto,
      text,
      html
    });

    return true;
  } catch (error) {
    console.error("Erro ao enviar email:", error);
    return false;
  }
}

async function enviarTelegramAvisoAdmin(texto, tipo = "default") {
  const token = String(process.env.TELEGRAM_BOT_TOKEN || "").trim();
  const chatId = obterChatIdTelegram(tipo);

  if (!token || !chatId) {
    return false;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TELEGRAM_TIMEOUT_MS);

  try {
    const url = `https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: texto,
        disable_web_page_preview: true
      }),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!res.ok) {
      console.error(`Erro ao enviar Telegram admin (tipo=${tipo}, chatId=${chatId}):`, await res.text());
      return false;
    }

    return true;
  } catch (error) {
    clearTimeout(timer);
    console.error("Erro ao enviar Telegram admin:", error);
    return false;
  }
}

async function notificarVendaAdmin({ tipo, pagamento, origem, telegramTipo = "default" }) {
  const p = enriquecerPagamento(pagamento);

  const credenciais = {
    usuario: p.cliente_usuario || null,
    senha: p.cliente_senha || null
  };

  const linhas = [
    `SG IPTV - ${tipo}`,
    "",
    `Plano: ${p.plano}`,
    `Valor: R$ ${p.valor}`,
    `Email: ${p.email}`,
    `WhatsApp cliente: ${p.telefone}`,
    credenciais?.usuario ? `Usuario: ${credenciais.usuario}` : null,
    credenciais?.senha ? `Senha: ${credenciais.senha}` : null,
    `Payment ID: ${p.payment_id}`,
    origem ? `Origem: ${origem}` : null,
    "",
    `Painel Admin: ${ADMIN_PANEL_URL}`
  ].filter(Boolean);

  const texto = linhas.join("\n");

  // Envia para o chat especifico do assunto (pix/cliente/revendedor/vencimento_1d etc).
  await enviarTelegramAvisoAdmin(texto, telegramTipo);

  await enviarEmailAvisoAdmin({
    assunto: `${tipo} - SG IPTV`,
    text: texto,
    html: `
      <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
        <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
          <h2 style="color:#facc15;">${escaparHtml(tipo)}</h2>
          <p><strong>Plano:</strong> ${escaparHtml(p.plano)}</p>
          <p><strong>Valor:</strong> R$ ${escaparHtml(p.valor)}</p>
          <p><strong>Email:</strong> ${escaparHtml(p.email)}</p>
          <p><strong>WhatsApp cliente:</strong> ${escaparHtml(p.telefone)}</p>
          ${credenciais?.usuario ? `<p><strong>Usuario:</strong> ${escaparHtml(credenciais.usuario)}</p>` : ""}
          ${credenciais?.senha ? `<p><strong>Senha:</strong> ${escaparHtml(credenciais.senha)}</p>` : ""}
          <p><strong>Payment ID:</strong> ${escaparHtml(p.payment_id)}</p>
          ${origem ? `<p><strong>Origem:</strong> ${escaparHtml(origem)}</p>` : ""}
          <hr style="border-color:#7e22ce;">
          ${criarBotaoPainelAdmin()}
        </div>
      </div>
    `
  });

  await enviarWhatsappAvisoAdmin(texto);
}

function phoneToBr(phoneDigits) {
  const digits = String(phoneDigits || "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.startsWith("55")) return `+${digits}`;
  return `+55${digits}`;
}

async function avisarVencimentosClientes() {
  const transporter = criarTransporterEmail();
  if (!transporter) return;

  // Evita spam: envia no maximo 1x por dia por tipo de aviso.
  const result = await db.query(`
    SELECT id, usuario, plano, vencimento, email, telefone, nome, aviso_3d_em, aviso_1d_em
    FROM clientes
    WHERE vencimento IS NOT NULL
  `);

  const agora = Date.now();
  const umDiaMs = 24 * 60 * 60 * 1000;

  for (const c of result.rows) {
    const venc = new Date(c.vencimento);
    if (Number.isNaN(venc.getTime())) continue;

    const diffDias = Math.ceil((venc.getTime() - agora) / umDiaMs);

    const deveAvisar3d = diffDias === 3 && (!c.aviso_3d_em || (agora - new Date(c.aviso_3d_em).getTime()) > umDiaMs);
    const deveAvisar1d = diffDias === 1 && (!c.aviso_1d_em || (agora - new Date(c.aviso_1d_em).getTime()) > umDiaMs);

    if (!deveAvisar3d && !deveAvisar1d) continue;

    const tipo = deveAvisar1d ? "Vencimento em 1 dia" : "Vencimento em 3 dias";
    const nome = String(c.nome || "").trim();
    const texto = `
${tipo} - SG IPTV

Cliente: ${nome || "-"}
Usuario: ${c.usuario}
Plano: ${c.plano}
Vencimento: ${formatarDataPtBr(c.vencimento)}
Email: ${c.email || "-"}
WhatsApp: ${c.telefone || "-"}

Painel Admin: ${ADMIN_PANEL_URL}
    `.trim();

    await transporter.sendMail({
      from: `"SG IPTV" <${process.env.EMAIL_USER}>`,
      to: ADMIN_EMAIL_VENCIMENTOS,
      subject: `${tipo} - ${c.usuario}`,
      text: texto
    });

    if (deveAvisar1d) {
      await enviarTelegramAvisoAdmin(texto, "vencimento_1d");
    }

    try {
      await db.query(
        `UPDATE clientes SET ${deveAvisar1d ? "aviso_1d_em" : "aviso_3d_em"} = NOW(), atualizado_em = NOW() WHERE id = $1`,
        [c.id]
      );
    } catch (error) {
      console.error("Erro ao salvar aviso de vencimento:", error);
    }
  }
}

async function enviarEmailVencimentoTeste({ dias, cliente }) {
  const transporter = criarTransporterEmail();
  if (!transporter) {
    throw new Error("Email nao configurado no backend. Defina SMTP_HOST/SMTP_USER/SMTP_PASS (Brevo) ou EMAIL_USER/EMAIL_PASS (Gmail).");
  }

  const tipo = `Vencimento em ${dias} dia${dias === 1 ? "" : "s"}`;
  const nome = String(cliente.nome || "").trim();

  const texto = `
${tipo} - SG IPTV

Cliente: ${nome || "-"}
Usuario: ${cliente.usuario}
Plano: ${cliente.plano}
Vencimento: ${formatarDataPtBr(cliente.vencimento)}
Email: ${cliente.email || "-"}
WhatsApp: ${cliente.telefone || "-"}

Painel Admin: ${ADMIN_PANEL_URL}
  `.trim();

  // EMAIL_FROM pode ser "Nome <email@dominio>" ou apenas "email@dominio".
  // Precisamos extrair o email real; caso contrario a Brevo rejeita com "valid sender email required".
  const baseFrom = String(process.env.EMAIL_FROM || "").trim();
  const fromEmail =
    extrairEmailFrom(baseFrom) ||
    String(process.env.SMTP_USER || process.env.EMAIL_USER || "").trim();
  const fromName =
    extrairNomeFrom(baseFrom) ||
    String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();
  const from = fromEmail ? `"${fromName}" <${fromEmail}>` : undefined;

  await transporter.sendMail({
    ...(from ? { from } : {}),
    to: ADMIN_EMAIL_VENCIMENTOS,
    subject: `${tipo} (TESTE) - ${cliente.usuario}`,
    text: texto
  });

  return { ok: true };
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
    SET status = $1,
        confirmado_em = NOW()
    WHERE payment_id = $2
    RETURNING *
    `,
    ["confirmado", String(pagamento.payment_id)]
  );

  const confirmado = result.rows[0] || pagamento;

  // Atualiza vencimento do cliente (renovacao) quando tivermos algum identificador do cliente.
  try {
    await aplicarRenovacaoCliente(confirmado);
    await limparTesteIptvDoCliente({
      usuario: confirmado.cliente_usuario,
      email: confirmado.email,
      telefone: confirmado.telefone
    });
    await garantirComissaoDoPagamentoConfirmado(confirmado);
  } catch (e) {
    console.error("Erro ao aplicar renovacao no cliente (continuando):", e);
  }

  if (!confirmado.notificado_em) {
    await notificarVendaAdmin({ tipo: "Pix recebido", pagamento: confirmado, origem, telegramTipo: "pix" });
    try {
      await db.query("UPDATE pagamentos SET notificado_em = NOW() WHERE payment_id = $1", [String(confirmado.payment_id)]);
    } catch (error) {
      console.error("Erro ao salvar notificado_em:", error);
    }
  }

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

function conexoesDoPlano(planoTexto) {
  const plano = String(planoTexto || "").toLowerCase();
  if (plano.includes("2 tela") || plano.includes("2 telas")) return 2;
  return 1;
}

function calcularValorComissaoPrimeiraVenda({ plano = "", dias = 0, conexoes = 1 } = {}) {
  const p = String(plano || "").toLowerCase();
  const d = Number(dias) || 0;
  const c = Number(conexoes) || 1;

  // Regras atuais (painel):
  // - Mensal 1 tela: R$ 10,00
  // - Mensal 2 telas: R$ 15,00
  // - 3 meses 1 tela: R$ 30,00
  const ehTresMeses = p.includes("3 mes") || d >= 90;
  const ehMensal = p.includes("mensal") || d === 30;

  if (ehTresMeses) return 30;
  if (ehMensal && c >= 2) return 15;
  if (ehMensal) return 10;
  return 0;
}

function calcularValorComissaoRenovacao({ valorPagamento = 0 } = {}) {
  const v = Number(valorPagamento) || 0;
  if (!Number.isFinite(v) || v <= 0) return 0;
  // Renovacao: 10% do valor do plano.
  return Math.round(v * 0.1 * 100) / 100;
}

async function garantirComissaoDoPagamentoConfirmado(pagamento) {
  // Cria comissao pendente para o revendedor vinculado ao cliente, sem duplicar.
  if (!pagamento || pagamento.status !== "confirmado") return;
  if (!pagamento.id) return; // precisamos do id para FK (pagamento_id)

  const usuario = String(pagamento.cliente_usuario || "").trim();
  // Evita parâmetro NULL "sem tipo" no Postgres em algumas expressões com $2/$3.
  // Preferimos string vazia e fazemos as checagens com "<> ''" no SQL.
  const email = pagamento.email ? String(pagamento.email).trim().toLowerCase() : "";
  const telefone = pagamento.telefone ? String(pagamento.telefone).replace(/\D/g, "") : "";
  if (!usuario && !email && !telefone) return;

  // IMPORTANTE: quando $2/$3 vem null, o Postgres pode não conseguir inferir o tipo do parâmetro
  // em expressões como "email = $2". Por isso fazemos cast explícito para text.
  let clienteRes;
  try {
    clienteRes = await db.query(
      `
      SELECT id, revendedor_id
      FROM clientes
      WHERE ($1 <> '' AND usuario = $1::text)
         OR ($2::text <> '' AND email = $2::text)
         OR ($3::text <> '' AND telefone = $3::text)
      ORDER BY atualizado_em DESC, id DESC
      LIMIT 1
      `,
      [usuario, email, telefone]
    );
  } catch (e) {
    console.error("Erro em comissao(cliente lookup):", e?.message || e, { usuario, email, telefone, pagamento_id: pagamento.id });
    throw e;
  }
  if (clienteRes.rows.length === 0) return;

  const cliente = clienteRes.rows[0];
  const revendedorId = cliente.revendedor_id ? Number(cliente.revendedor_id) : 0;
  if (!revendedorId) return;

  const jaExiste = await db.query(`SELECT 1 FROM comissoes WHERE pagamento_id = $1 LIMIT 1`, [Number(pagamento.id)]);
  if (jaExiste.rows.length > 0) return;

  let tipo = "renovacao";
  try {
    const prev = await db.query(
      `
      SELECT 1
      FROM pagamentos p
      WHERE p.status = 'confirmado'
        AND p.id <> $1
        AND (
          ($2::text <> '' AND p.cliente_usuario = $2::text)
          OR ($3::text <> '' AND p.email = $3::text)
          OR ($4::text <> '' AND p.telefone = $4::text)
        )
      LIMIT 1
      `,
      [Number(pagamento.id), usuario, email, telefone]
    );
    if (prev.rows.length === 0) tipo = "primeira_compra";
  } catch (e) {
    console.error("Erro em comissao(prev check):", e?.message || e, { usuario, email, telefone, pagamento_id: pagamento.id });
    tipo = "renovacao";
  }

  const dias = diasPlano(pagamento);
  const conexoes = conexoesDoPlano(pagamento.plano);
  const valor =
    tipo === "primeira_compra"
      ? calcularValorComissaoPrimeiraVenda({ plano: pagamento.plano, dias, conexoes })
      : calcularValorComissaoRenovacao({ valorPagamento: pagamento.valor });
  if (!valor || valor <= 0) return;

  try {
    await db.query(
      `
      INSERT INTO comissoes (revendedor_id, cliente_id, pagamento_id, tipo, valor, status, criado_em, atualizado_em)
      VALUES ($1, $2, $3, $4, $5, 'pendente', NOW(), NOW())
      `,
      [revendedorId, Number(cliente.id), Number(pagamento.id), tipo, Number(valor)]
    );
  } catch (e) {
    console.error("Erro em comissao(insert):", e?.message || e, { revendedorId, clienteId: cliente.id, pagamento_id: pagamento.id, tipo, valor });
    throw e;
  }
}

async function aplicarRenovacaoCliente(pagamento) {
  if (!pagamento) return;

  const usuario = String(pagamento.cliente_usuario || "").trim();
  const senha = String(pagamento.cliente_senha || "").trim() || null;
  const email = pagamento.email ? String(pagamento.email).trim().toLowerCase() : "";
  const telefone = pagamento.telefone ? String(pagamento.telefone).replace(/\D/g, "") : "";

  // Precisamos de algum identificador para achar o cliente.
  if (!usuario && !email && !telefone) return;

  const dias = diasPlano(pagamento);
  const conexoes = conexoesDoPlano(pagamento.plano);

  // Pega vencimento atual para somar a partir do maior entre vencimento e agora.
  const clienteAtual = await db.query(
    `
    SELECT id, vencimento
    FROM clientes
    WHERE ($1 <> '' AND usuario = $1)
       OR ($2::text <> '' AND email = $2::text)
       OR ($3::text <> '' AND telefone = $3::text)
    ORDER BY atualizado_em DESC, id DESC
    LIMIT 1
    `,
    [usuario, email, telefone]
  );

  if (clienteAtual.rows.length === 0) return;
  const c = clienteAtual.rows[0];

  const agora = new Date();
  const vencAtual = c.vencimento ? new Date(c.vencimento) : null;
  const base = (vencAtual && vencAtual > agora) ? vencAtual : agora;
  const novoVenc = new Date(base);
  novoVenc.setDate(novoVenc.getDate() + dias);

  await db.query(
    `
    UPDATE clientes
    SET plano = $2,
        conexoes = $3,
        vencimento = $4,
        email = COALESCE($5, email),
        telefone = COALESCE($6, telefone),
        senha = COALESCE($7, senha),
        atualizado_em = NOW()
    WHERE id = $1
    `,
    [
      c.id,
      String(pagamento.plano || "").trim() || "MENSAL",
      conexoes,
      novoVenc.toISOString(),
      email,
      telefone,
      senha || null
    ]
  );
}

async function limparTesteIptvDoCliente({ usuario = "", email = null, telefone = null } = {}) {
  const u = String(usuario || "").trim();
  const e = email ? String(email).trim().toLowerCase() : "";
  const t = telefone ? String(telefone).replace(/\D/g, "") : "";

  if (!u && !e && !t) return;

  try {
    await db.query(
      `
      DELETE FROM testes_iptv
      WHERE ($1 <> '' AND login = $1)
         OR ($2::text <> '' AND email = $2::text)
         OR ($3::text <> '' AND telefone = $3::text)
      `,
      [u, e, t]
    );
  } catch (e2) {
    console.warn("Aviso: falha ao limpar teste_iptv do cliente:", e2?.message || e2);
  }
}

async function backfillComissoesRecentes() {
  // Gera comissoes faltantes para pagamentos confirmados recentes
  // (ex.: confirmados antes da feature de comissoes existir).
  try {
    const result = await db.query(
      `
      SELECT p.*
      FROM pagamentos p
      LEFT JOIN comissoes c ON c.pagamento_id = p.id
      WHERE p.status = 'confirmado'
        AND c.id IS NULL
        AND p.confirmado_em >= NOW() - INTERVAL '60 days'
      ORDER BY p.confirmado_em DESC, p.id DESC
      LIMIT 200
      `
    );

    for (const p of result.rows) {
      try {
        await garantirComissaoDoPagamentoConfirmado(p);
      } catch (e) {
        console.error("Erro ao backfill de comissao (continuando):", e?.message || e);
      }
    }
  } catch (e) {
    console.error("Erro ao rodar backfillComissoesRecentes:", e?.message || e);
  }
}

let pixSyncEmAndamento = false;
async function sincronizarPixPendentesBackground() {
  if (pixSyncEmAndamento) return;
  pixSyncEmAndamento = true;
  try {
    // Limpeza leve antes de sincronizar.
    await cancelarPagamentosPixExpirados();
    await limparPagamentosCanceladosAntigos();

    // Busca os mais recentes primeiro. Só PIX "de verdade" (payment_id numérico do MercadoPago).
    const result = await db.query(
      `
      SELECT *
      FROM pagamentos
      WHERE status = $1
        AND payment_id ~ '^[0-9]+$'
        AND criado_em >= NOW() - INTERVAL '2 days'
      ORDER BY criado_em DESC
      LIMIT 50
      `,
      ["pendente"]
    );

    for (const pagamento of result.rows) {
      try {
        await sincronizarPagamentoMercadoPago(pagamento);
      } catch (e) {
        // Não derrubar o loop por um pagamento quebrado.
        console.error("Falha ao sincronizar pagamento pendente (continuando):", e);
      }
    }
  } catch (error) {
    console.error("Erro no sincronizador de PIX pendente:", error);
  } finally {
    pixSyncEmAndamento = false;
  }
}

async function cancelarPagamentosPixExpirados() {
  try {
    await db.query(
      `
      UPDATE pagamentos
      SET status = $1,
          cancelado_em = NOW()
      WHERE status = $2
      AND criado_em <= NOW() - (($3::text) || ' minutes')::interval
      `,
      ["cancelado", "pendente", PIX_EXPIRACAO_MINUTOS]
    );
  } catch (error) {
    // Se a coluna ainda nao existir (migracao async), faz fallback sem cancelado_em.
    console.error("Erro ao cancelar Pix expirados (com cancelado_em). Tentando fallback:", error);
    try {
      await db.query(
        `
        UPDATE pagamentos
        SET status = $1
        WHERE status = $2
        AND criado_em <= NOW() - (($3::text) || ' minutes')::interval
        `,
        ["cancelado", "pendente", PIX_EXPIRACAO_MINUTOS]
      );
    } catch (fallbackError) {
      console.error("Erro ao cancelar Pix expirados (fallback). Continuando:", fallbackError);
    }
  }
}

async function limparPagamentosCanceladosAntigos() {
  try {
    await db.query(
      `
      DELETE FROM pagamentos
      WHERE status = $1
      AND COALESCE(cancelado_em, criado_em) <= NOW() - (($2::text) || ' minutes')::interval
      `,
      ["cancelado", PIX_EXPIRACAO_MINUTOS]
    );
  } catch (error) {
    // Fallback quando cancelado_em ainda nao existe.
    console.error("Erro ao limpar cancelados (com cancelado_em). Tentando fallback:", error);
    try {
      await db.query(
        `
        DELETE FROM pagamentos
        WHERE status = $1
        AND criado_em <= NOW() - (($2::text) || ' minutes')::interval
        `,
        ["cancelado", PIX_EXPIRACAO_MINUTOS]
      );
    } catch (fallbackError) {
      console.error("Erro ao limpar cancelados (fallback). Continuando:", fallbackError);
    }
  }
}

function verificarTokenRevendedor(req, res, next) {
  const authorization = String(req.headers.authorization || "").trim();
  const token = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : authorization;

  if (!token) {
    return res.status(401).json({ error: "Token nao enviado" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload?.role !== "revendedor" || !payload?.rid) {
      return res.status(401).json({ error: "Token invalido" });
    }
    req.revendedor = { id: payload.rid };
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token invalido" });
  }
}

function gerarCodigoRevendedor() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 8; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

app.post("/login", limiteLogin, (req, res) => {
  const { usuario, senha } = req.body;

  adminCredenciaisValidas(usuario, senha)
    .then(valido => {
      if (!valido) {
        return res.status(401).json({ error: "Usuário ou senha inválidos" });
      }

      const token = jwt.sign({ usuario }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({ token });
    })
    .catch(error => {
      console.error("Erro ao validar login admin:", error);
      return res.status(500).json({ error: "Erro ao processar login." });
    });
});

app.post("/revendedor/register", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const senha = String(req.body?.senha || "").trim();
  const nomeCompleto = String(req.body?.nome_completo || "").trim() || null;
  const pixCpf = String(req.body?.pix_cpf || "").replace(/\D/g, "") || null;
  const bancoNome = String(req.body?.banco_nome || "").trim() || null;

  if (!email || !senha) {
    return res.status(400).json({ error: "Informe email e senha." });
  }

  if (pixCpf && pixCpf.length !== 11) {
    return res.status(400).json({ error: "PIX deve ser CPF (11 digitos)." });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);

    let codigo = gerarCodigoRevendedor();
    for (let tentativas = 0; tentativas < 5; tentativas++) {
      const existe = await db.query("SELECT 1 FROM revendedores WHERE codigo = $1", [codigo]);
      if (existe.rows.length === 0) break;
      codigo = gerarCodigoRevendedor();
    }

    await db.query(
      `
      INSERT INTO revendedores (codigo, email, senha_hash, nome_completo, pix_cpf, banco_nome, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
      [codigo, email, senhaHash, nomeCompleto, pixCpf, bancoNome, "pendente"]
    );

    await enviarTelegramAvisoAdmin(
      [
        "SG IPTV - Novo revendedor cadastrado",
        "",
        `Email: ${email}`,
        nomeCompleto ? `Nome: ${nomeCompleto}` : null,
        pixCpf ? `PIX (CPF): ${pixCpf}` : null,
        `Codigo: ${codigo}`,
        "Status: pendente",
        "",
        `Painel Admin: ${ADMIN_PANEL_URL}`
      ].filter(Boolean).join("\n"),
      "revendedor"
    );

    return res.json({
      ok: true,
      codigo,
      status: "pendente",
      mensagem: "Cadastro realizado com sucesso. Aguarde ate 24 horas para aprovacao do master."
    });
  } catch (error) {
    console.error("Erro ao cadastrar revendedor:", error);
    return res.status(500).json({ error: "Erro ao cadastrar revendedor." });
  }
});

app.post("/revendedor/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const senha = String(req.body?.senha || "").trim();

  if (!email || !senha) {
    return res.status(400).json({ error: "Informe email e senha." });
  }

  try {
    const result = await db.query("SELECT * FROM revendedores WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Email ou senha invalidos." });
    }

    const rev = result.rows[0];
    if (rev.status !== "aprovado") {
      return res.status(403).json({ error: "Seu cadastro ainda nao foi aprovado. Aguarde ate 24 horas." });
    }
    const ok = await bcrypt.compare(senha, rev.senha_hash);
    if (!ok) {
      return res.status(401).json({ error: "Email ou senha invalidos." });
    }

    const token = jwt.sign({ role: "revendedor", rid: rev.id }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ ok: true, token });
  } catch (error) {
    console.error("Erro login revendedor:", error);
    return res.status(500).json({ error: "Erro ao entrar." });
  }
});

app.get("/revendedor/me", verificarTokenRevendedor, async (req, res) => {
  const rid = req.revendedor.id;

  try {
    const rev = await db.query("SELECT id, codigo, email, nome_completo, pix_cpf, banco_nome FROM revendedores WHERE id = $1", [rid]);
    if (rev.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });

    const pend = await db.query(
      "SELECT COALESCE(SUM(valor),0) AS total FROM comissoes WHERE revendedor_id = $1 AND status = 'pendente'",
      [rid]
    );

    const stats = await db.query(
      `
      WITH mes AS (
        SELECT date_trunc('month', NOW()) AS inicio,
               date_trunc('month', NOW()) + interval '1 month' AS fim
      )
      SELECT
        COALESCE((
          SELECT COUNT(DISTINCT cl.id)
          FROM pagamentos p
          JOIN clientes cl ON cl.usuario = p.cliente_usuario
          JOIN mes m ON TRUE
          WHERE p.status = 'confirmado'
            AND p.confirmado_em >= m.inicio
            AND p.confirmado_em < m.fim
            AND cl.revendedor_id = $1
        ), 0) AS clientes_ativos_mes
      `,
      [rid]
    );

    const clientesAtivosMes = Number(stats.rows[0]?.clientes_ativos_mes || 0);
    // Bonus: mais de 10 vendas ativas no mes => R$ 50,00
    const bonusMes = clientesAtivosMes > 10 ? 50 : 0;

    return res.json({
      ok: true,
      revendedor: rev.rows[0],
      resumo: {
        total_pendente: Number(pend.rows[0]?.total || 0),
        clientes_ativos_mes: clientesAtivosMes,
        bonus_mes: bonusMes
      }
    });
  } catch (error) {
    console.error("Erro revendedor/me:", error);
    return res.status(500).json({ error: "Erro ao carregar painel." });
  }
});

app.get("/revendedor/comissoes", verificarTokenRevendedor, async (req, res) => {
  const rid = req.revendedor.id;

  try {
    const result = await db.query(
      `
      SELECT
        c.id,
        c.tipo,
        c.valor,
        c.status,
        c.transacao_id,
        c.criado_em,
        c.pago_em,
        c.pagamento_id,
        c.cliente_id,
        cl.usuario AS cliente_usuario,
        cl.nome AS cliente_nome,
        cl.email AS cliente_email,
        cl.telefone AS cliente_telefone
      FROM comissoes c
      JOIN clientes cl ON cl.id = c.cliente_id
      WHERE c.revendedor_id = $1
      ORDER BY c.id DESC
      LIMIT 200
      `,
      [rid]
    );

    return res.json({ ok: true, comissoes: result.rows });
  } catch (error) {
    console.error("Erro revendedor/comissoes:", error);
    return res.status(500).json({ error: "Erro ao buscar comissoes." });
  }
});

db.query("SELECT NOW()")
  .then(res => console.log("Banco conectado:", res.rows))
  .catch(err => console.error("Erro no banco:", err));

// Garante tabela pagamentos antes de qualquer ALTER TABLE (bases novas ou legadas podem nao ter).
db.query(`
  CREATE TABLE IF NOT EXISTS pagamentos (
    id BIGSERIAL PRIMARY KEY,
    email TEXT,
    telefone TEXT,
    plano TEXT NOT NULL,
    valor NUMERIC(10, 2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pendente',
    payment_id TEXT UNIQUE NOT NULL,
    cliente_usuario TEXT,
    cliente_senha TEXT,
    confirmado_em TIMESTAMPTZ,
    notificado_em TIMESTAMPTZ,
    cancelado_em TIMESTAMPTZ,
    aviso_24h_enviado_em TIMESTAMPTZ,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT pagamentos_status_check CHECK (status IN ('pendente', 'confirmado', 'cancelado'))
  )
`)
  .then(() => console.log("Tabela pagamentos OK"))
  .catch(err => console.error("Erro ao garantir tabela pagamentos:", err));

async function limparRevendedoresSemClientesAtivos() {
  try {
    await db.query(
      `
      DELETE FROM revendedores r
      WHERE r.criado_em <= NOW() - interval '7 days'
      AND NOT EXISTS (
        SELECT 1
        FROM clientes c
        WHERE c.revendedor_id = r.id
        AND c.vencimento > NOW()
      )
      `
    );
  } catch (error) {
    console.error("Erro ao limpar revendedores sem clientes ativos:", error);
  }
}

// Rodamos em background: evita acumular revendedores sem nenhum cliente ativo.
setInterval(limparRevendedoresSemClientesAtivos, 12 * 60 * 60 * 1000);
limparRevendedoresSemClientesAtivos();

// Limpa a tabela de testes a cada hora (mantem apenas 24h de historico).
setInterval(limparTestesIptvAntigos, 60 * 60 * 1000);
limparTestesIptvAntigos();

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS aviso_24h_enviado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna aviso_24h_enviado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna aviso_24h_enviado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS cancelado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna pagamentos.cancelado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.cancelado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS confirmado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna pagamentos.confirmado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.confirmado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS notificado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna pagamentos.notificado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.notificado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS origem TEXT`)
  .then(() => console.log("Coluna pagamentos.origem OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.origem:", err));

db.query(`ALTER TABLE pagamentos ALTER COLUMN origem SET DEFAULT 'pix'`)
  .then(() => {})
  .catch(() => {});

db.query(`UPDATE pagamentos SET origem = 'pix' WHERE origem IS NULL`)
  .then(() => {})
  .catch(() => {});

// Bases legadas (ex: import/restores) podem nao ter criado_em/atualizado_em.
// Sem isso, rotas de listagem/relatorio e limpeza por tempo estouram 500.
db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()`)
  .then(() => console.log("Coluna pagamentos.criado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.criado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()`)
  .then(() => console.log("Coluna pagamentos.atualizado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.atualizado_em:", err));

// Se a coluna existia mas tinha nulos, preenche para manter queries funcionando.
db.query(`UPDATE pagamentos SET criado_em = NOW() WHERE criado_em IS NULL`)
  .then(() => {})
  .catch(() => {});

db.query(`UPDATE pagamentos SET atualizado_em = NOW() WHERE atualizado_em IS NULL`)
  .then(() => {})
  .catch(() => {});

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()`)
  .then(() => console.log("Coluna pagamentos.atualizado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.atualizado_em:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS cliente_usuario TEXT`)
  .then(() => console.log("Coluna pagamentos.cliente_usuario OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.cliente_usuario:", err));

db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS cliente_senha TEXT`)
  .then(() => console.log("Coluna pagamentos.cliente_senha OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.cliente_senha:", err));

// Bases restauradas/legadas podem nao ter a coluna telefone (WhatsApp) na tabela pagamentos.
db.query(`ALTER TABLE pagamentos ADD COLUMN IF NOT EXISTS telefone TEXT`)
  .then(() => console.log("Coluna pagamentos.telefone OK"))
  .catch(err => console.error("Erro ao garantir coluna pagamentos.telefone:", err));

// Permite confirmacao manual sem exigir email/telefone no DB (Pix normal segue validando no backend).
db.query(`ALTER TABLE pagamentos ALTER COLUMN email DROP NOT NULL`)
  .then(() => console.log("Pagamentos.email nullable OK"))
  .catch(() => null);
db.query(`ALTER TABLE pagamentos ALTER COLUMN telefone DROP NOT NULL`)
  .then(() => console.log("Pagamentos.telefone nullable OK"))
  .catch(() => null);

db.query(`
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
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`)
  .then(() => console.log("Tabela clientes OK"))
  .catch(err => console.error("Erro ao garantir tabela clientes:", err));

db.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS aviso_3d_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna clientes.aviso_3d_em OK"))
  .catch(err => console.error("Erro ao garantir coluna clientes.aviso_3d_em:", err));

db.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS aviso_1d_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna clientes.aviso_1d_em OK"))
  .catch(err => console.error("Erro ao garantir coluna clientes.aviso_1d_em:", err));

db.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS revendedor_id BIGINT`)
  .then(() => console.log("Coluna clientes.revendedor_id OK"))
  .catch(err => console.error("Erro ao garantir coluna clientes.revendedor_id:", err));

db.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS revendedor_vinculado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna clientes.revendedor_vinculado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna clientes.revendedor_vinculado_em:", err));

db.query(`
  CREATE TABLE IF NOT EXISTS revendedores (
    id BIGSERIAL PRIMARY KEY,
    codigo TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    nome_completo TEXT,
    pix_cpf TEXT UNIQUE,
    banco_nome TEXT,
    status TEXT NOT NULL DEFAULT 'pendente',
    aprovado_em TIMESTAMPTZ,
    reprovado_em TIMESTAMPTZ,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`)
  .then(() => console.log("Tabela revendedores OK"))
  .catch(err => console.error("Erro ao garantir tabela revendedores:", err));

db.query(`ALTER TABLE revendedores ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pendente'`)
  .then(() => console.log("Coluna revendedores.status OK"))
  .catch(err => console.error("Erro ao garantir coluna revendedores.status:", err));

db.query(`ALTER TABLE revendedores ADD COLUMN IF NOT EXISTS aprovado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna revendedores.aprovado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna revendedores.aprovado_em:", err));

db.query(`ALTER TABLE revendedores ADD COLUMN IF NOT EXISTS reprovado_em TIMESTAMPTZ`)
  .then(() => console.log("Coluna revendedores.reprovado_em OK"))
  .catch(err => console.error("Erro ao garantir coluna revendedores.reprovado_em:", err));

db.query(`
  CREATE TABLE IF NOT EXISTS comissoes (
    id BIGSERIAL PRIMARY KEY,
    revendedor_id BIGINT NOT NULL REFERENCES revendedores(id) ON DELETE CASCADE,
    cliente_id BIGINT NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
    pagamento_id BIGINT NOT NULL REFERENCES pagamentos(id) ON DELETE CASCADE,
    tipo TEXT NOT NULL,
    valor NUMERIC(10, 2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pendente',
    transacao_id TEXT,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pago_em TIMESTAMPTZ,
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT comissoes_tipo_check CHECK (tipo IN ('primeira_compra', 'renovacao')),
    CONSTRAINT comissoes_status_check CHECK (status IN ('pendente', 'processando', 'pago', 'falhou'))
  )
`)
  .then(() => console.log("Tabela comissoes OK"))
  .catch(err => console.error("Erro ao garantir tabela comissoes:", err));

// Bonus do revendedor (pagamento manual registrado pelo admin).
db.query(`
  CREATE TABLE IF NOT EXISTS bonus_pagamentos (
    id BIGSERIAL PRIMARY KEY,
    revendedor_id BIGINT NOT NULL REFERENCES revendedores(id) ON DELETE CASCADE,
    mes DATE NOT NULL,
    valor NUMERIC(10, 2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pendente',
    transacao_id TEXT,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pago_em TIMESTAMPTZ,
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT bonus_pagamentos_status_check CHECK (status IN ('pendente', 'pago', 'falhou'))
  )
`)
  .then(() => console.log("Tabela bonus_pagamentos OK"))
  .catch(err => console.error("Erro ao garantir tabela bonus_pagamentos:", err));

// Bases novas/limpas podem nao ter a tabela testes_iptv ainda.
db.query(`
  CREATE TABLE IF NOT EXISTS testes_iptv (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    telefone TEXT NOT NULL,
    resposta TEXT NOT NULL,
    login TEXT,
    senha TEXT,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`)
  .then(() => console.log("Tabela testes_iptv OK"))
  .catch(err => console.error("Erro ao garantir tabela testes_iptv:", err));

db.query(`CREATE INDEX IF NOT EXISTS testes_iptv_email_telefone_idx ON testes_iptv (email, telefone)`)
  .then(() => console.log("Indice testes_iptv_email_telefone_idx OK"))
  .catch(err => console.error("Erro ao garantir indice testes_iptv_email_telefone_idx:", err));

db.query(`ALTER TABLE testes_iptv ADD COLUMN IF NOT EXISTS login TEXT`)
  .then(() => console.log("Coluna testes_iptv.login OK"))
  .catch(err => console.error("Erro ao garantir coluna testes_iptv.login:", err));

db.query(`ALTER TABLE testes_iptv ADD COLUMN IF NOT EXISTS senha TEXT`)
  .then(() => console.log("Coluna testes_iptv.senha OK"))
  .catch(err => console.error("Erro ao garantir coluna testes_iptv.senha:", err));

app.get("/", (req, res) => {
  res.send("Backend funcionando 🚀");
});

// Garante que pagamentos PIX pendentes sejam sincronizados mesmo se o webhook falhar.
// (Ex.: URL antiga, instabilidade do provedor, etc.)
if (PIX_SYNC_INTERVAL_MS > 0) {
  setInterval(sincronizarPixPendentesBackground, PIX_SYNC_INTERVAL_MS).unref?.();
  // Roda uma vez no boot (não bloqueia o start do servidor).
  setTimeout(sincronizarPixPendentesBackground, 5_000).unref?.();
  console.log(`Sincronizador PIX pendente ativo: a cada ${PIX_SYNC_INTERVAL_MS}ms`);
}

// Garante comissoes para pagamentos confirmados recentes (feature nova).
setTimeout(backfillComissoesRecentes, 10_000).unref?.();

app.post("/pix", limitePublico, async (req, res) => {
  let { planoId, valor, email, telefone, cliente_usuario, cliente_senha } = req.body;
  const planoSelecionado = obterPlano(planoId, valor);

  if (!planoSelecionado) {
    return res.status(400).json({ error: "Escolha um plano valido." });
  }

  ({ email, telefone } = normalizarContato({ email, telefone }));

  const erroContato = validarContato({ email, telefone });
  if (erroContato) {
    return res.status(400).json({ error: erroContato });
  }

  const plano = planoSelecionado.nome;
  valor = planoSelecionado.valor;

  const clienteUsuario = String(cliente_usuario || "").trim() || null;
  const clienteSenha = String(cliente_senha || "").trim() || null;

  try {
    console.log("PIX /pix solicitado:", { planoId, valor, email, telefone });
    const payment = new Payment(client);
    const pixExpiraEm = adicionarTempo(new Date(), PIX_EXPIRACAO_MINUTOS, "minutos");

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano,
        payment_method_id: "pix",
        payer: { email },
        date_of_expiration: pixExpiraEm,
        notification_url: WEBHOOK_SECRET
          ? `${NOTIFICATION_URL}?secret=${encodeURIComponent(WEBHOOK_SECRET)}`
          : NOTIFICATION_URL
      }
    });

    const paymentId = String(result.id);
    console.log("PIX /pix criado no MercadoPago:", { paymentId });

    const insertResult = await db.query(
      `
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id, cliente_usuario, cliente_senha, origem)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `,
      [email, telefone, plano, valor, "pendente", paymentId, clienteUsuario, clienteSenha, "pix"]
    );
    console.log("PIX /pix registrado no banco:", { paymentId, inserted: insertResult?.rowCount ?? 0 });

    const data = result.point_of_interaction.transaction_data;

    await notificarVendaAdmin({
      tipo: "Novo Pix gerado",
      pagamento: { email, telefone, plano, valor, payment_id: paymentId },
      origem: "pix",
      telegramTipo: "pix"
    });

    res.json({
      qr_code: data.qr_code,
      qr_base64: data.qr_code_base64,
      payment_id: paymentId,
      pix_expira_em: pixExpiraEm,
      pix_expiracao_minutos: PIX_EXPIRACAO_MINUTOS
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

  ({ email, telefone } = normalizarContato({ email, telefone }));
  paymentId = String(paymentId).trim();

  const erroContato = validarContato({ email, telefone });
  if (erroContato) {
    return res.status(400).json({ error: erroContato });
  }

  try {
    await cancelarPagamentosPixExpirados();
    await limparPagamentosCanceladosAntigos();

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
    await limparPagamentosCanceladosAntigos();

    const result = await db.query("SELECT * FROM pagamentos ORDER BY id DESC");
    const lista = result.rows.map(enriquecerPagamento);

    for (const pagamento of lista) {
      if (pagamento.status !== "confirmado") continue;
      if (!pagamento.data_expiracao) continue;
      if (pagamento.aviso_24h_enviado_em) continue;

      const expiraEm = new Date(pagamento.data_expiracao).getTime();
      if (Number.isNaN(expiraEm)) continue;

      const restanteMs = expiraEm - Date.now();
      if (restanteMs <= 0) continue;

      if (restanteMs <= 24 * 60 * 60 * 1000) {
        // Nunca deixe a listagem de pagamentos falhar por causa de notificacao.
        try {
          await enviarEmailAvisoAdmin({
            assunto: "Plano com menos de 24h - SG IPTV",
            text: `
Plano com menos de 24h

Email: ${pagamento.email}
WhatsApp: ${pagamento.telefone}
Plano: ${pagamento.plano}
Valor: R$ ${pagamento.valor}
Expira em: ${formatarDataPtBr(pagamento.data_expiracao)}
Payment ID: ${pagamento.payment_id}

Painel Admin: ${ADMIN_PANEL_URL}
          `,
            html: `
            <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
              <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #facc15; border-radius:14px; padding:25px;">
                <h2 style="color:#facc15;">Plano com menos de 24h</h2>
                <p><strong>Email:</strong> ${escaparHtml(pagamento.email)}</p>
                <p><strong>WhatsApp:</strong> ${escaparHtml(pagamento.telefone)}</p>
                <p><strong>Plano:</strong> ${escaparHtml(pagamento.plano)}</p>
                <p><strong>Valor:</strong> R$ ${escaparHtml(pagamento.valor)}</p>
                <p><strong>Expira em:</strong> ${escaparHtml(formatarDataPtBr(pagamento.data_expiracao))}</p>
                <p><strong>Payment ID:</strong> ${escaparHtml(pagamento.payment_id)}</p>
                ${criarBotaoPainelAdmin()}
              </div>
            </div>
          `
          });
        } catch (e) {
          console.error("Falha ao enviar email 24h (continuando):", e);
        }

        await db.query(
          `
          UPDATE pagamentos
          SET aviso_24h_enviado_em = NOW()
          WHERE id = $1
          AND aviso_24h_enviado_em IS NULL
          `,
          [pagamento.id]
        );
      }
    }

    res.json(lista);
  } catch (error) {
    console.error("Erro ao buscar pagamentos:", error);
    res.status(500).json({
      error: "Erro ao buscar pagamentos",
      detail: String(error?.message || error)
    });
  }
});

app.post("/admin/pix/teste", verificarToken, async (req, res) => {
  let { planoId, valor, email, telefone, cliente_usuario, cliente_senha } = req.body || {};
  const planoSelecionado = obterPlano(planoId, valor);

  if (!planoSelecionado) {
    return res.status(400).json({ error: "Escolha um plano valido." });
  }

  ({ email, telefone } = normalizarContato({ email, telefone }));

  const erroContato = validarContato({ email, telefone });
  if (erroContato) {
    return res.status(400).json({ error: erroContato });
  }

  const plano = `TESTE PIX - ${planoSelecionado.nome}`;
  valor = planoSelecionado.valor;

  const clienteUsuario = String(cliente_usuario || "").trim() || null;
  const clienteSenha = String(cliente_senha || "").trim() || null;

  try {
    const payment = new Payment(client);
    const pixExpiraEm = adicionarTempo(new Date(), PIX_EXPIRACAO_MINUTOS, "minutos");

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano,
        payment_method_id: "pix",
        payer: { email },
        date_of_expiration: pixExpiraEm,
        notification_url: WEBHOOK_SECRET
          ? `${NOTIFICATION_URL}?secret=${encodeURIComponent(WEBHOOK_SECRET)}`
          : NOTIFICATION_URL
      }
    });

    const paymentId = String(result.id);

    await db.query(
      `
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id, cliente_usuario, cliente_senha)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
      [email, telefone, plano, valor, "pendente", paymentId, clienteUsuario, clienteSenha]
    );

    const data = result.point_of_interaction.transaction_data;

    // Notifica admin (email/telegram/whatsapp se configurado) para validar o fluxo.
    await notificarVendaAdmin({
      tipo: "Novo Pix gerado (teste)",
      pagamento: { email, telefone, plano, valor, payment_id: paymentId },
      origem: "admin/pix/teste"
    });

    res.json({
      ok: true,
      qr_code: data.qr_code,
      qr_base64: data.qr_code_base64,
      payment_id: paymentId,
      pix_expira_em: pixExpiraEm,
      pix_expiracao_minutos: PIX_EXPIRACAO_MINUTOS
    });
  } catch (error) {
    console.error("Erro PIX teste:", error);
    res.status(500).json({ error: "Erro ao gerar Pix teste" });
  }
});

// Importa um pagamento do Mercado Pago pelo ID (util quando um pagamento real foi feito mas nao ficou registrado no banco).
// Observacao: nem sempre o Mercado Pago retorna telefone; nesses casos, salvamos telefone como null.
app.post("/admin/pix/importar", verificarToken, async (req, res) => {
  const paymentId = String(req.body?.payment_id || req.body?.paymentId || "").trim();
  if (!paymentId || !/^[0-9]+$/.test(paymentId)) {
    return res.status(400).json({ error: "Informe payment_id numerico." });
  }

  try {
    const payment = new Payment(client);
    const mp = await payment.get({ id: paymentId });

    const plano = String(mp?.description || "Pagamento PIX (importado)").trim();
    const valor = Number(mp?.transaction_amount || 0);
    const email = String(mp?.payer?.email || "").trim() || null;
    const telefone = null;

    const status =
      mp?.status === "approved" ? "confirmado" :
      mp?.status === "cancelled" ? "cancelado" :
      "pendente";

    // Cria o registro se nao existir; se existir, atualiza status/origem.
    const existente = await db.query(
      "SELECT * FROM pagamentos WHERE payment_id = $1 LIMIT 1",
      [paymentId]
    );

    let salvo;
    if (existente.rows.length === 0) {
      const insert = await db.query(
        `
        INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id, origem, confirmado_em)
        VALUES ($1, $2, $3, $4, $5, $6, $7, ${status === "confirmado" ? "NOW()" : "NULL"})
        RETURNING *
        `,
        [email, telefone, plano, valor, status, paymentId, "pix_import"]
      );
      salvo = insert.rows[0];
    } else {
      const update = await db.query(
        `
        UPDATE pagamentos
        SET status = $1,
            origem = $2,
            confirmado_em = CASE WHEN $1 = 'confirmado' AND confirmado_em IS NULL THEN NOW() ELSE confirmado_em END
        WHERE payment_id = $3
        RETURNING *
        `,
        [status, "pix_import", paymentId]
      );
      salvo = update.rows[0];
    }

    // Se veio aprovado e ainda nao notificou, notifica agora.
    if (salvo?.status === "confirmado" && !salvo?.notificado_em) {
      await notificarVendaAdmin({ tipo: "Pix recebido (importado)", pagamento: salvo, origem: "pix_import", telegramTipo: "pix" });
      try {
        await db.query("UPDATE pagamentos SET notificado_em = NOW() WHERE payment_id = $1", [paymentId]);
      } catch {}
    }

    return res.json({ ok: true, pagamento: enriquecerPagamento(salvo), mp_status: mp?.status || null });
  } catch (error) {
    console.error("Erro ao importar pagamento MP:", error);
    return res.status(500).json({ error: "Erro ao importar pagamento do Mercado Pago.", detail: String(error?.message || error) });
  }
});

app.get("/pagamentos/mes", verificarToken, async (req, res) => {
  const year = Number(req.query.year);
  const month = Number(req.query.month);

  if (!year || !month || month < 1 || month > 12) {
    return res.status(400).json({ error: "Informe year e month (1-12)." });
  }

  const inicio = new Date(Date.UTC(year, month - 1, 1, 0, 0, 0));
  const fim = new Date(Date.UTC(year, month, 1, 0, 0, 0));

  try {
    await cancelarPagamentosPixExpirados();
    await limparPagamentosCanceladosAntigos();

    const result = await db.query(
      `
      SELECT *
      FROM pagamentos
      WHERE status = $1
      AND COALESCE(confirmado_em, criado_em) >= $2
      AND COALESCE(confirmado_em, criado_em) < $3
      ORDER BY COALESCE(confirmado_em, criado_em) DESC, id DESC
      `,
      ["confirmado", inicio.toISOString(), fim.toISOString()]
    );

    const lista = result.rows.map(enriquecerPagamento);
    const total = lista.reduce((acc, p) => acc + Number(p.valor || 0), 0);

    res.json({
      ok: true,
      year,
      month,
      total,
      quantidade: lista.length,
      pagamentos: lista
    });
  } catch (error) {
    console.error("Erro ao buscar pagamentos do mes:", error);
    res.status(500).json({
      error: "Erro ao buscar pagamentos do mes",
      detail: String(error?.message || error)
    });
  }
});

app.post("/pagamentos/:id/avisar", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `
      SELECT *
      FROM pagamentos
      WHERE id = $1
      LIMIT 1
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Pagamento nao encontrado." });
    }

    const pagamento = enriquecerPagamento(result.rows[0]);

    await enviarEmailAvisoAdmin({
      assunto: "Aviso manual - SG IPTV",
      text: `
Aviso manual enviado pelo admin

Email: ${pagamento.email}
WhatsApp: ${pagamento.telefone}
Plano: ${pagamento.plano}
Valor: R$ ${pagamento.valor}
Expira em: ${pagamento.data_expiracao ? formatarDataPtBr(pagamento.data_expiracao) : "Nao informado"}
Payment ID: ${pagamento.payment_id}

Painel Admin: ${ADMIN_PANEL_URL}
      `,
      html: `
        <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
          <div style="max-width:720px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
            <h2 style="color:#facc15;">Aviso manual enviado</h2>
            <p><strong>Email:</strong> ${escaparHtml(pagamento.email)}</p>
            <p><strong>WhatsApp:</strong> ${escaparHtml(pagamento.telefone)}</p>
            <p><strong>Plano:</strong> ${escaparHtml(pagamento.plano)}</p>
            <p><strong>Valor:</strong> R$ ${escaparHtml(pagamento.valor)}</p>
            <p><strong>Expira em:</strong> ${escaparHtml(pagamento.data_expiracao ? formatarDataPtBr(pagamento.data_expiracao) : "Nao informado")}</p>
            <p><strong>Payment ID:</strong> ${escaparHtml(pagamento.payment_id)}</p>
            ${criarBotaoPainelAdmin()}
          </div>
        </div>
      `
    });

    await db.query(
      `
      UPDATE pagamentos
      SET aviso_24h_enviado_em = NOW()
      WHERE id = $1
      `,
      [id]
    );

    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao avisar cliente:", error);
    return res.status(500).json({ error: "Erro ao enviar aviso." });
  }
});

app.get("/clientes", verificarToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT *
      FROM clientes
      ORDER BY vencimento DESC, id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar clientes:", error);
    res.status(500).json({ error: "Erro ao buscar clientes" });
  }
});

app.put("/clientes/:id", verificarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, email, telefone, conexoes, vencimento, revendedor_codigo } = req.body || {};

  let conexoesNumero = null;
  if (conexoes !== undefined && conexoes !== null && String(conexoes).trim() !== "") {
    const parsed = Number.parseInt(String(conexoes), 10);
    if (Number.isNaN(parsed) || (parsed !== 1 && parsed !== 2)) {
      return res.status(400).json({ error: "Conexoes invalido. Use 1 ou 2." });
    }
    conexoesNumero = parsed;
  }

  let vencimentoDate = null;
  if (vencimento !== undefined && vencimento !== null && String(vencimento).trim() !== "") {
    const d = new Date(String(vencimento));
    if (Number.isNaN(d.getTime())) {
      return res.status(400).json({ error: "Vencimento invalido. Use uma data/hora valida." });
    }
    vencimentoDate = d.toISOString();
  }

  try {
    let revendedorId = null;
    const codigo = String(revendedor_codigo || "").trim();
    if (codigo) {
      const rev = await db.query(
        `
        SELECT id, status
        FROM revendedores
        WHERE codigo = $1
        LIMIT 1
        `,
        [codigo]
      );

      if (rev.rows.length === 0) {
        return res.status(400).json({ error: "Codigo de revendedor nao encontrado." });
      }
      if (String(rev.rows[0].status || "").toLowerCase() !== "aprovado") {
        return res.status(400).json({ error: "Revendedor ainda nao aprovado." });
      }
      revendedorId = rev.rows[0].id;
    }

    const result = await db.query(
      `
      UPDATE clientes
      SET nome = $1,
          email = $2,
          telefone = $3,
          conexoes = COALESCE($4, conexoes),
          vencimento = COALESCE($5, vencimento),
          revendedor_id = COALESCE($6, revendedor_id),
          revendedor_vinculado_em = CASE WHEN $6 IS NOT NULL THEN NOW() ELSE revendedor_vinculado_em END,
          atualizado_em = NOW()
      WHERE id = $7
      RETURNING *
      `,
      [
        nome ? String(nome).trim() : null,
        email ? String(email).trim().toLowerCase() : null,
        telefone ? String(telefone).replace(/\\D/g, "") : null,
        conexoesNumero,
        vencimentoDate,
        revendedorId,
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Cliente nao encontrado." });
    }

    res.json({ ok: true, cliente: result.rows[0] });
  } catch (error) {
    console.error("Erro ao atualizar cliente:", error);
    res.status(500).json({ error: "Erro ao atualizar cliente" });
  }
});

app.get("/revendedores", verificarToken, async (req, res) => {
  try {
    const result = await db.query(
      `
      WITH mes AS (
        SELECT date_trunc('month', NOW()) AS inicio,
               date_trunc('month', NOW()) + interval '1 month' AS fim
      )
      SELECT
        r.id,
        r.codigo,
        r.email,
        r.nome_completo,
        r.pix_cpf,
        r.status,
        COALESCE(SUM(CASE WHEN c.status = 'pendente' THEN c.valor ELSE 0 END), 0) AS total_pendente,
        COALESCE(MAX(CASE WHEN bp.status = 'pago' THEN bp.valor ELSE 0 END), 0) AS bonus_pago_mes,
        COALESCE((
          SELECT COUNT(DISTINCT cl.id)
          FROM pagamentos p
          JOIN clientes cl ON cl.usuario = p.cliente_usuario
          JOIN mes m ON TRUE
          WHERE p.status = 'confirmado'
            AND p.confirmado_em >= m.inicio
            AND p.confirmado_em < m.fim
            AND cl.revendedor_id = r.id
        ), 0) AS clientes_ativos_mes,
        CASE
          WHEN COALESCE((
            SELECT COUNT(DISTINCT cl2.id)
            FROM pagamentos p2
            JOIN clientes cl2 ON cl2.usuario = p2.cliente_usuario
            JOIN mes m2 ON TRUE
            WHERE p2.status = 'confirmado'
              AND p2.confirmado_em >= m2.inicio
              AND p2.confirmado_em < m2.fim
              AND cl2.revendedor_id = r.id
          ), 0) > 10 THEN 50
          ELSE 0
        END AS bonus_mes
      FROM revendedores r
      LEFT JOIN comissoes c ON c.revendedor_id = r.id
      LEFT JOIN bonus_pagamentos bp
        ON bp.revendedor_id = r.id
       AND bp.mes = date_trunc('month', NOW())::date
       AND bp.status = 'pago'
      GROUP BY r.id
      ORDER BY r.id DESC
      `
    );

    const revendedores = result.rows.map(r => {
      const bonusMes = Number(r.bonus_mes) || 0;
      const bonusPago = Number(r.bonus_pago_mes) || 0;
      const bonusPendente = Math.max(0, bonusMes - bonusPago);
      return { ...r, bonus_pago_mes: bonusPago, bonus_pendente_mes: bonusPendente };
    });

    res.json({ ok: true, revendedores });
  } catch (error) {
    console.error("Erro ao buscar revendedores:", error);
    res.status(500).json({ error: "Erro ao buscar revendedores." });
  }
});

app.get("/revendedores/:id/comissoes", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();

  if (!id) {
    return res.status(400).json({ error: "Informe o id do revendedor." });
  }

  try {
    const result = await db.query(
      `
      SELECT
        c.*,
        cl.usuario AS cliente_usuario,
        cl.nome AS cliente_nome,
        cl.email AS cliente_email,
        cl.telefone AS cliente_telefone
      FROM comissoes c
      JOIN clientes cl ON cl.id = c.cliente_id
      WHERE c.revendedor_id = $1
      ORDER BY c.id DESC
      LIMIT 200
      `,
      [id]
    );

    res.json({ ok: true, comissoes: result.rows });
  } catch (error) {
    console.error("Erro ao buscar comissoes do revendedor:", error);
    res.status(500).json({ error: "Erro ao buscar comissoes do revendedor." });
  }
});

app.get("/revendedores/:id/clientes", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();

  if (!id) {
    return res.status(400).json({ error: "Informe o id do revendedor." });
  }

  try {
    const result = await db.query(
      `
      SELECT id, usuario, plano, vencimento, nome, email, telefone
      FROM clientes
      WHERE revendedor_id = $1
      ORDER BY vencimento DESC, id DESC
      `,
      [id]
    );

    return res.json({ ok: true, clientes: result.rows });
  } catch (error) {
    console.error("Erro ao buscar clientes do revendedor:", error);
    return res.status(500).json({ error: "Erro ao buscar clientes do revendedor." });
  }
});

app.put("/revendedores/:id/aprovar", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ error: "Informe o id do revendedor." });

  try {
    const result = await db.query(
      `
      UPDATE revendedores
      SET status = 'aprovado',
          aprovado_em = NOW(),
          reprovado_em = NULL,
          atualizado_em = NOW()
      WHERE id = $1
      RETURNING id, codigo, email, status
      `,
      [id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });
    const rev = result.rows[0];

    // Confirma no Telegram do revendedor que foi aprovado.
    await enviarTelegramAvisoAdmin(
      [
        "SG IPTV - Revendedor aprovado",
        "",
        `Email: ${rev.email}`,
        `Codigo: ${rev.codigo}`,
        "Status: aprovado",
        "",
        `Painel Admin: ${ADMIN_PANEL_URL}`
      ].join("\n"),
      "revendedor"
    );

    return res.json({ ok: true, revendedor: rev });
  } catch (error) {
    console.error("Erro ao aprovar revendedor:", error);
    return res.status(500).json({ error: "Erro ao aprovar revendedor." });
  }
});

app.put("/revendedores/:id/reprovar", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ error: "Informe o id do revendedor." });

  try {
    const result = await db.query(
      `
      UPDATE revendedores
      SET status = 'reprovado',
          reprovado_em = NOW(),
          aprovado_em = NULL,
          atualizado_em = NOW()
      WHERE id = $1
      RETURNING id, codigo, email, status
      `,
      [id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });
    const rev = result.rows[0];

    // Confirma no Telegram do revendedor que foi reprovado.
    await enviarTelegramAvisoAdmin(
      [
        "SG IPTV - Revendedor reprovado",
        "",
        `Email: ${rev.email}`,
        `Codigo: ${rev.codigo}`,
        "Status: reprovado",
        "",
        `Painel Admin: ${ADMIN_PANEL_URL}`
      ].join("\n"),
      "revendedor"
    );

    return res.json({ ok: true, revendedor: rev });
  } catch (error) {
    console.error("Erro ao reprovar revendedor:", error);
    return res.status(500).json({ error: "Erro ao reprovar revendedor." });
  }
});

app.put("/pagamentos/:id/confirmar", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const atual = await db.query("SELECT * FROM pagamentos WHERE id = $1 LIMIT 1", [id]);
    if (atual.rows.length === 0) return res.status(404).json({ error: "Pagamento nao encontrado." });

    // Confirma e roda fluxo completo (renova cliente, comissao, limpa teste, notifica se aplicavel).
    await confirmarPagamentoRecebido(atual.rows[0], "admin_manual");

    res.json({ ok: true, message: "Pagamento confirmado" });
  } catch (error) {
    console.error("Erro ao confirmar pagamento:", error);
    res.status(500).json({ error: "Erro ao confirmar pagamento" });
  }
});

// Marcar comissoes como pagas (fluxo manual: admin faz o PIX e registra o comprovante).
app.post("/revendedores/:id/comissoes/pagar", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();
  const transacaoId = req.body && req.body.transacao_id ? String(req.body.transacao_id).trim() : null;
  const notificar = req.body && typeof req.body.notificar === "boolean" ? req.body.notificar : true;

  if (!id) return res.status(400).json({ error: "Informe o id do revendedor." });

  try {
    const revRes = await db.query(`SELECT id, codigo, email, nome_completo, pix_cpf FROM revendedores WHERE id = $1 LIMIT 1`, [id]);
    if (revRes.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });
    const rev = revRes.rows[0];

    const pend = await db.query(
      `
      SELECT COALESCE(SUM(valor), 0) AS total, COUNT(*) AS qtd
      FROM comissoes
      WHERE revendedor_id = $1 AND status = 'pendente'
      `,
      [id]
    );

    const total = Number(pend.rows[0]?.total || 0);
    const qtd = Number(pend.rows[0]?.qtd || 0);
    if (qtd <= 0) return res.json({ ok: true, message: "Sem comissoes pendentes.", total: 0, qtd: 0 });

    await db.query(
      `
      UPDATE comissoes
      SET status = 'pago',
          transacao_id = COALESCE($2::text, transacao_id),
          pago_em = NOW(),
          atualizado_em = NOW()
      WHERE revendedor_id = $1 AND status = 'pendente'
      `,
      [id, transacaoId]
    );

    if (notificar && rev.email) {
      const assunto = "SG IPTV - Comissao paga";
      const text = [
        "SG IPTV - Comissao paga",
        "",
        `Revendedor: ${rev.nome_completo || "-"} (${rev.codigo || "-"})`,
        `PIX/CPF: ${rev.pix_cpf || "-"}`,
        `Valor: R$ ${total.toFixed(2)}`,
        `Itens: ${qtd}`,
        transacaoId ? `Comprovante/ID: ${transacaoId}` : "",
        "",
        "Pagamento registrado no painel Admin."
      ].filter(Boolean).join("\n");
      await enviarEmailPara(rev.email, { assunto, text, html: `<pre style="font-family:Arial, sans-serif; white-space:pre-wrap;">${text}</pre>` });
    }

    return res.json({ ok: true, total, qtd });
  } catch (error) {
    console.error("Erro ao marcar comissoes como pagas:", error);
    return res.status(500).json({ error: "Erro ao marcar comissoes como pagas." });
  }
});

// Marcar bonus do mes como pago (fluxo manual: admin faz o PIX e registra o comprovante).
app.post("/revendedores/:id/bonus/pagar", verificarToken, async (req, res) => {
  const id = String(req.params.id || "").trim();
  const transacaoId = req.body && req.body.transacao_id ? String(req.body.transacao_id).trim() : null;
  const notificar = req.body && typeof req.body.notificar === "boolean" ? req.body.notificar : true;

  if (!id) return res.status(400).json({ error: "Informe o id do revendedor." });

  try {
    const revRes = await db.query(`SELECT id, codigo, email, nome_completo, pix_cpf FROM revendedores WHERE id = $1 LIMIT 1`, [id]);
    if (revRes.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });
    const rev = revRes.rows[0];

    // Recalcula bonus do mes (mesma regra da listagem).
    const bonusRes = await db.query(
      `
      WITH mes AS (
        SELECT date_trunc('month', NOW()) AS inicio,
               date_trunc('month', NOW()) + interval '1 month' AS fim
      )
      SELECT
        CASE
          WHEN COALESCE((
            SELECT COUNT(DISTINCT cl2.id)
            FROM pagamentos p2
            JOIN clientes cl2 ON cl2.usuario = p2.cliente_usuario
            JOIN mes m2 ON TRUE
            WHERE p2.status = 'confirmado'
              AND p2.confirmado_em >= m2.inicio
              AND p2.confirmado_em < m2.fim
              AND cl2.revendedor_id = $1
          ), 0) > 10 THEN 50
          ELSE 0
        END AS bonus_mes,
        COALESCE((
          SELECT bp.valor
          FROM bonus_pagamentos bp
          WHERE bp.revendedor_id = $1
            AND bp.mes = date_trunc('month', NOW())::date
            AND bp.status = 'pago'
          ORDER BY bp.id DESC
          LIMIT 1
        ), 0) AS bonus_pago_mes
      `,
      [id]
    );

    const bonusMes = Number(bonusRes.rows[0]?.bonus_mes || 0);
    const bonusPago = Number(bonusRes.rows[0]?.bonus_pago_mes || 0);
    const bonusPendente = Math.max(0, bonusMes - bonusPago);

    if (bonusPendente <= 0) {
      return res.json({ ok: true, message: "Sem bonus pendente no mes.", valor: 0 });
    }

    await db.query(
      `
      INSERT INTO bonus_pagamentos (revendedor_id, mes, valor, status, transacao_id, criado_em, pago_em, atualizado_em)
      VALUES ($1, date_trunc('month', NOW())::date, $2, 'pago', $3, NOW(), NOW(), NOW())
      `,
      [id, bonusPendente, transacaoId]
    );

    if (notificar && rev.email) {
      const assunto = "SG IPTV - Bonus pago";
      const text = [
        "SG IPTV - Bonus pago",
        "",
        `Revendedor: ${rev.nome_completo || "-"} (${rev.codigo || "-"})`,
        `PIX/CPF: ${rev.pix_cpf || "-"}`,
        `Valor: R$ ${bonusPendente.toFixed(2)}`,
        transacaoId ? `Comprovante/ID: ${transacaoId}` : "",
        "",
        "Pagamento registrado no painel Admin."
      ].filter(Boolean).join("\n");
      await enviarEmailPara(rev.email, { assunto, text, html: `<pre style="font-family:Arial, sans-serif; white-space:pre-wrap;">${text}</pre>` });
    }

    return res.json({ ok: true, valor: bonusPendente });
  } catch (error) {
    console.error("Erro ao marcar bonus como pago:", error);
    return res.status(500).json({ error: "Erro ao marcar bonus como pago." });
  }
});

// Atualiza campos auxiliares do pagamento (para testes/auditoria no painel).
app.put("/pagamentos/:id/detalhes", verificarToken, async (req, res) => {
  const { id } = req.params;
  const cliente_usuario = req.body?.cliente_usuario ? String(req.body.cliente_usuario).trim() : null;
  const cliente_senha = req.body?.cliente_senha ? String(req.body.cliente_senha).trim() : null;
  const email = req.body?.email ? String(req.body.email).trim().toLowerCase() : null;
  const telefone = req.body?.telefone ? String(req.body.telefone).replace(/\D/g, "") : null;
  const origem = req.body?.origem ? String(req.body.origem).trim().toLowerCase() : null;

  const origemFinal = origem === "pix" || origem === "dinheiro" ? origem : null;

  try {
    // Se for um pagamento associado a um cliente, permite "puxar do cadastro" e salvar aqui.
    // Aceitamos email/telefone vazios como "nao alterar". Para limpar, o admin deve excluir e recriar.
    const result = await db.query(
      `
      UPDATE pagamentos
      SET cliente_usuario = COALESCE($2, cliente_usuario),
          cliente_senha = COALESCE($3, cliente_senha),
          email = COALESCE($4, email),
          telefone = COALESCE($5, telefone),
          origem = COALESCE($6, origem),
          atualizado_em = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [id, cliente_usuario, cliente_senha, email, telefone, origemFinal]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Pagamento nao encontrado." });
    }

    const atualizado = result.rows[0];

    // Se o pagamento ja estiver confirmado, tenta reconciliar dados (plano/vencimento/comissao).
    if (String(atualizado.status) === "confirmado") {
      try {
        await aplicarRenovacaoCliente(atualizado);
        await limparTesteIptvDoCliente({
          usuario: atualizado.cliente_usuario,
          email: atualizado.email,
          telefone: atualizado.telefone
        });
        await garantirComissaoDoPagamentoConfirmado(atualizado);
      } catch (e) {
        console.error("Aviso: falha ao reconciliar pagamento confirmado (continuando):", e?.message || e);
      }
    }

    return res.json({ ok: true, pagamento: enriquecerPagamento(atualizado) });
  } catch (error) {
    console.error("Erro ao atualizar detalhes do pagamento:", error);
    return res.status(500).json({ error: "Erro ao atualizar detalhes do pagamento.", detail: String(error?.message || error) });
  }
});

// Excluir pagamento (apenas para limpar testes/pendentes/cancelados no painel).
app.delete("/pagamentos/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const atual = await db.query(
      `SELECT id, status, plano, payment_id FROM pagamentos WHERE id = $1 LIMIT 1`,
      [id]
    );

    if (atual.rows.length === 0) {
      return res.status(404).json({ error: "Pagamento nao encontrado." });
    }

    const p = atual.rows[0];
    const plano = String(p.plano || "");
    const paymentId = String(p.payment_id || "");
    const status = String(p.status || "");

    await db.query(`DELETE FROM pagamentos WHERE id = $1`, [id]);
    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao excluir pagamento:", error);
    return res.status(500).json({ error: "Erro ao excluir pagamento.", detail: String(error?.message || error) });
  }
});

// Excluir teste IPTV (apenas limpeza de testes no painel).
app.delete("/testes-iptv/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const atual = await db.query(`SELECT id FROM testes_iptv WHERE id = $1 LIMIT 1`, [id]);
    if (atual.rows.length === 0) return res.status(404).json({ error: "Teste nao encontrado." });

    await db.query(`DELETE FROM testes_iptv WHERE id = $1`, [id]);
    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao excluir teste IPTV:", error);
    return res.status(500).json({ error: "Erro ao excluir teste IPTV.", detail: String(error?.message || error) });
  }
});

// Excluir cliente (apenas limpeza de cadastros de teste/errados no painel).
app.delete("/clientes/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const atual = await db.query(`SELECT id FROM clientes WHERE id = $1 LIMIT 1`, [id]);
    if (atual.rows.length === 0) return res.status(404).json({ error: "Cliente nao encontrado." });

    await db.query(`DELETE FROM clientes WHERE id = $1`, [id]);
    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao excluir cliente:", error);
    return res.status(500).json({ error: "Erro ao excluir cliente.", detail: String(error?.message || error) });
  }
});

// Excluir revendedor (limpeza no painel).
app.delete("/revendedores/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const atual = await db.query(`SELECT id FROM revendedores WHERE id = $1 LIMIT 1`, [id]);
    if (atual.rows.length === 0) return res.status(404).json({ error: "Revendedor nao encontrado." });

    await db.query(`DELETE FROM revendedores WHERE id = $1`, [id]);
    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao excluir revendedor:", error);
    return res.status(500).json({ error: "Erro ao excluir revendedor.", detail: String(error?.message || error) });
  }
});

// Confirmacao manual (pagamento em dinheiro).
app.post("/pagamentos/dinheiro", verificarToken, async (req, res) => {
  const {
    email,
    telefone,
    plano,
    valor,
    cliente_usuario,
    cliente_senha,
    confirmado_em
  } = req.body || {};

  const emailNorm = String(email || "").trim().toLowerCase();
  const telNorm = String(telefone || "").replace(/\D/g, "");
  const planoNorm = String(plano || "").trim();
  const valorNum = Number(valor);

  // Pagamento em dinheiro: obrigatorio apenas plano + valor.
  // Email/WhatsApp sao opcionais (podem vir vazios) e servem apenas para registro/relatorio.
  if (!planoNorm || !Number.isFinite(valorNum) || valorNum <= 0) {
    return res.status(400).json({ error: "Informe plano e valor." });
  }

  const paymentId = `DINHEIRO-${Date.now()}`;
  const confirmadoEm = confirmado_em ? new Date(confirmado_em) : new Date();

  try {
    const inserted = await db.query(
      `
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id, cliente_usuario, cliente_senha, confirmado_em, criado_em, atualizado_em, origem)
      VALUES ($1, $2, $3, $4, 'confirmado', $5, $6, $7, $8, NOW(), NOW(), 'dinheiro')
      RETURNING *
      `,
      [
        emailNorm || null,
        telNorm || null,
        planoNorm,
        valorNum,
        paymentId,
        cliente_usuario ? String(cliente_usuario).trim() : null,
        cliente_senha ? String(cliente_senha).trim() : null,
        confirmadoEm
      ]
    );

    // Renovacao do cliente (se houver login/email/telefone).
    try {
      await aplicarRenovacaoCliente(inserted.rows[0]);
      await garantirComissaoDoPagamentoConfirmado(inserted.rows[0]);
    } catch (e) {
      console.error("Erro ao aplicar renovacao no cliente (dinheiro):", e);
    }

    return res.json({ ok: true, pagamento: enriquecerPagamento(inserted.rows[0]) });
  } catch (error) {
    console.error("Erro ao confirmar pagamento em dinheiro:", error);
    return res.status(500).json({
      error: "Erro ao confirmar pagamento em dinheiro.",
      detail: String(error?.message || error)
    });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    if (!webhookSecretValido(req)) {
      return res.status(401).json({ error: "Webhook sem autorizacao." });
    }

    const paymentId = req.body?.data?.id;

    if (!paymentId) return res.sendStatus(200);

    // Confirma via rotina central (marca confirmado_em, notifica, renova cliente).
    const pagamentoResult = await db.query(
      "SELECT * FROM pagamentos WHERE payment_id = $1 ORDER BY id DESC LIMIT 1",
      [String(paymentId)]
    );

    if (pagamentoResult.rows.length > 0) {
      await sincronizarPagamentoMercadoPago(pagamentoResult.rows[0]);
    }

    res.sendStatus(200);

  } catch (error) {
    console.error("Erro webhook:", error);
    res.sendStatus(500);
  }
});

app.post("/cliente/consulta", limitePublico, async (req, res) => {
  let { email, telefone, usuario, senha } = req.body;

  const modoCliente = Boolean(usuario || senha);

  if (!modoCliente) {
    return res.status(400).json({ error: "Informe usuario e senha." });
  }

  if (modoCliente) {
    usuario = String(usuario || "").trim();
    senha = String(senha || "").trim();

    if (!usuario || !senha) {
      return res.status(400).json({ error: "Informe usuario e senha." });
    }

    try {
      const result = await db.query(
        `
        SELECT *
        FROM clientes
        WHERE usuario = $1
        AND senha = $2
        LIMIT 1
        `,
        [usuario, senha]
      );

      if (result.rows.length === 0) {
        const testeResult = await db.query(
          `
          SELECT *
          FROM testes_iptv
          WHERE login = $1
          AND senha = $2
          ORDER BY criado_em DESC, id DESC
          LIMIT 1
          `,
          [usuario, senha]
        );

        if (testeResult.rows.length === 0) {
          return res.status(404).json({ error: "Cliente nao encontrado." });
        }

        const teste = enriquecerTeste(testeResult.rows[0]);

        return res.json({
          ok: true,
          cliente: {
            tipoCliente: "teste",
            email: teste.email,
            telefone: teste.telefone,
            loginAreaCliente: teste.login || usuario,
            senhaAreaCliente: teste.senha || senha,
            ultimoPagamento: null,
            ultimoTeste: {
              ...teste,
              login: teste.login || usuario,
              senha: teste.senha || senha
            }
          }
        });
      }

      const cliente = result.rows[0];

      // Busca (se houver) o codigo do revendedor vinculado, para exibir no painel do cliente.
      let revendedorCodigo = null;
      if (cliente.revendedor_id) {
        try {
          const rev = await db.query(`SELECT codigo FROM revendedores WHERE id = $1 LIMIT 1`, [cliente.revendedor_id]);
          revendedorCodigo = rev.rows[0]?.codigo || null;
        } catch {}
      }

      avisarVencimentosClientes().catch(err => console.error("Erro avisos vencimento:", err));

      return res.json({
        ok: true,
        cliente: {
          tipoCliente: "cliente",
          usuario: cliente.usuario,
          senha: cliente.senha,
          plano: cliente.plano,
          criado_em: cliente.criado_em,
          vencimento: cliente.vencimento,
          nome: cliente.nome,
          email: cliente.email,
          telefone: cliente.telefone,
          revendedor_codigo: revendedorCodigo
        }
      });
    } catch (error) {
      console.error("Erro ao consultar cliente por usuario:", error);
      return res.status(500).json({ error: "Erro ao consultar cliente." });
    }
  }

  // Modo contato (email/WhatsApp) foi desativado.
  if (!email || !telefone) {
    return res.status(400).json({ error: "Acesso por email/WhatsApp desativado. Use usuario e senha." });
  }

  ({ email, telefone } = normalizarContato({ email, telefone }));

  const erroContato = validarContato({ email, telefone });
  if (erroContato) {
    return res.status(400).json({ error: erroContato });
  }

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

    const ultimoPagamento = pagamentoResult.rows[0]
      ? enriquecerPagamento(pagamentoResult.rows[0])
      : null;
    const ultimoTeste = testeResult.rows[0]
      ? (() => {
        const teste = enriquecerTeste(testeResult.rows[0]);
        const dadosTeste = extrairLoginSenha(teste.resposta);

        return {
          ...teste,
          login: dadosTeste.login,
          senha: dadosTeste.senha
        };
      })()
      : null;

    if (!ultimoPagamento && !ultimoTeste) {
      return res.status(404).json({
        error: "Nenhum plano ou teste encontrado para este email e WhatsApp."
      });
    }

    // Se houver teste recente e o pagamento nao estiver confirmado, priorizamos o painel de teste.
    const usarPainelTeste = !!ultimoTeste && (!ultimoPagamento || ultimoPagamento.status !== "confirmado");

    return res.json({
      ok: true,
      cliente: {
        tipoCliente: usarPainelTeste ? "teste" : "pagamento",
        email,
        telefone,
        loginAreaCliente: email,
        senhaAreaCliente: telefone,
        ultimoPagamento,
        ultimoTeste
      }
    });

  } catch (error) {
    console.error("Erro ao consultar cliente:", error);
    res.status(500).json({ error: "Erro ao consultar área do cliente." });
  }
});

app.post("/admin/teste-emails-vencimento", verificarToken, async (req, res) => {
  try {
    const { usuario } = req.body || {};

    if (!usuario) {
      return res.status(400).json({ error: "Informe o usuario do cliente." });
    }

    const result = await db.query(
      `
      SELECT usuario, plano, vencimento, email, telefone, nome
      FROM clientes
      WHERE usuario = $1
      LIMIT 1
      `,
      [String(usuario).trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Cliente nao encontrado." });
    }

    const cliente = result.rows[0];

    try {
      await enviarEmailVencimentoTeste({ dias: 3, cliente });
      await enviarEmailVencimentoTeste({ dias: 1, cliente });
    } catch (mailError) {
      return res.status(400).json({ error: String(mailError?.message || mailError || "Falha ao enviar email.") });
    }

    // Tambem envia Telegram para validar o canal de vencimentos.
    // Se TELEGRAM_CHAT_ID_VENCIMENTO_3D nao existir, cai no chat base.
    const baseTexto = (dias) => `
Vencimento em ${dias} dia${dias === 1 ? "" : "s"} (TESTE) - SG IPTV

Cliente: ${cliente.nome || "-"}
Usuario: ${cliente.usuario}
Plano: ${cliente.plano}
Vencimento: ${formatarDataPtBr(cliente.vencimento)}
Email: ${cliente.email || "-"}
WhatsApp: ${cliente.telefone || "-"}

Painel Admin: ${ADMIN_PANEL_URL}
    `.trim();

    await enviarTelegramAvisoAdmin(baseTexto(3), "vencimento_3d");
    await enviarTelegramAvisoAdmin(baseTexto(1), "vencimento_1d");

    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao enviar emails teste:", error);
    return res.status(500).json({ error: String(error?.message || "Erro ao enviar emails teste.") });
  }
});

app.post("/admin/telegram/teste", verificarToken, async (req, res) => {
  try {
    const { texto, tipo } = req.body || {};
    const msg = String(texto || "Teste Telegram - SG IPTV").trim();

    const tipoMsg = String(tipo || "default").trim();
    const ok = await enviarTelegramAvisoAdmin(msg, tipoMsg);
    if (!ok) {
      return res.status(400).json({ error: "Telegram nao configurado (TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID) ou falha ao enviar." });
    }

    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao testar Telegram:", error);
    return res.status(500).json({ error: "Erro ao testar Telegram." });
  }
});

app.post("/admin/email/teste", verificarToken, async (req, res) => {
  try {
    const { assunto, texto } = req.body || {};
    const subj = String(assunto || "Teste Email - SG IPTV").trim();
    const body = String(texto || "Teste de envio de email do backend SG IPTV.").trim();

    const ok = await enviarEmailAvisoAdmin({
      assunto: subj,
      text: body,
      html: `<pre style="font-family:Arial, sans-serif; white-space:pre-wrap;">${escaparHtml(body)}</pre>`
    });

    if (!ok) {
      return res.status(400).json({
        error: "Email nao enviado. Verifique BREVO_API_KEY+EMAIL_FROM, ou SMTP_HOST/SMTP_USER/SMTP_PASS, ou EMAIL_USER/EMAIL_PASS."
      });
    }

    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao testar email:", error);
    return res.status(500).json({ error: "Erro ao testar email." });
  }
});

app.post("/teste-iptv", limitePublico, async (req, res) => {
  let { email, telefone, tipoTeste } = req.body;

  if (!email || !telefone) {
    return res.status(400).json({ error: "Informe email e WhatsApp para gerar o teste." });
  }

  ({ email, telefone } = normalizarContato({ email, telefone }));

  const erroContato = validarContato({ email, telefone });
  if (erroContato) {
    return res.status(400).json({ error: erroContato });
  }

  tipoTeste = tipoTeste || "iptv_com_adulto";

  if (!TESTE_URLS[tipoTeste]) {
    return res.status(400).json({ error: "Escolha um tipo de teste valido." });
  }

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
    const agoraIso = new Date().toISOString();
    const vencimentoTeste = adicionarTempo(agoraIso, TESTE_DURACAO_HORAS, "horas");

    // Garante que o cliente consegue entrar na Area do Cliente imediatamente apos gerar o teste,
    // sem depender do envio de email. (usuario = login, senha = senha extraidos do painel IPTV)
    try {
      await db.query(
        `
        INSERT INTO clientes (usuario, senha, plano, conexoes, criado_em, vencimento, email, telefone, atualizado_em)
        VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, NOW())
        ON CONFLICT (usuario) DO UPDATE
          SET senha = EXCLUDED.senha,
              plano = EXCLUDED.plano,
              conexoes = EXCLUDED.conexoes,
              vencimento = EXCLUDED.vencimento,
              email = EXCLUDED.email,
              telefone = EXCLUDED.telefone,
              atualizado_em = NOW()
        `,
        [dadosTeste.login, dadosTeste.senha, "TESTE GRATUITO", 1, vencimentoTeste, email, telefone]
      );
    } catch (clienteError) {
      console.error("Erro ao salvar teste em clientes:", clienteError);
    }

    try {
      await db.query(
        `
        INSERT INTO testes_iptv (email, telefone, resposta, login, senha)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [email, telefone, textoFormatado, dadosTeste.login, dadosTeste.senha]
      );
    } catch (dbError) {
      // Em bases legadas pode existir UNIQUE em email/telefone.
      // Nesses casos, atualizamos o registro existente para evitar erro 500.
      if (dbError?.code === "23505") {
        const atualizacao = await db.query(
          `
          UPDATE testes_iptv
          SET telefone = $2,
              resposta = $3,
              login = $4,
              senha = $5,
              criado_em = NOW()
          WHERE email = $1 OR telefone = $2
          RETURNING id
          `,
          [email, telefone, textoFormatado, dadosTeste.login, dadosTeste.senha]
        );

        if (atualizacao.rows.length === 0) {
          throw dbError;
        }
      } else {
        throw dbError;
      }
    }

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

    await enviarTelegramAvisoAdmin(
      [
        "SG IPTV - Novo cliente (teste gerado)",
        "",
        `Tipo: ${tipoTeste}`,
        `Email: ${email}`,
        `WhatsApp: ${telefone}`,
        `Login: ${dadosTeste.login}`,
        `Senha: ${dadosTeste.senha}`,
        "",
        `Painel Admin: ${ADMIN_PANEL_URL}`
      ].join("\n"),
      "cliente"
    );

    res.json({
      ok: true,
      message: emailEnviado
        ? "Teste gerado e enviado para seu email."
        : "Teste gerado. As configurações aparecerão na tela.",
      resposta: textoFormatado,
      emailEnviado,
      usuario: dadosTeste.login,
      senha: dadosTeste.senha,
      vencimento: vencimentoTeste
    });

  } catch (error) {
    console.error("Erro ao gerar teste IPTV:", error);
    res.status(500).json({ error: "Erro ao gerar teste IPTV." });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log("🚀 Backend rodando na porta", PORT);

  // Backfill: garante comissoes para pagamentos confirmados que ficaram sem comissao
  // (por exemplo: pagamento confirmado antes/fora do fluxo normal).
  // Delay pequeno para o banco e as rotinas de "garantir tabelas/colunas" concluirem.
  setTimeout(() => {
    try {
      backfillComissoesRecentes();
    } catch (e) {
      console.error("Erro ao iniciar backfillComissoesRecentes:", e?.message || e);
    }
  }, 8000);
});

app.get("/testes-iptv", verificarToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT * FROM testes_iptv
      ORDER BY id DESC
    `);

    const lista = [];

    for (const item of result.rows) {
      const teste = enriquecerTeste(item);
      const criadoEm = new Date(teste.criado_em);
      const diasDesdeCriacao = Number.isNaN(criadoEm.getTime())
        ? 0
        : Math.floor((Date.now() - criadoEm.getTime()) / (24 * 60 * 60 * 1000));

      let liberarCredenciais = true;

      if (diasDesdeCriacao >= 10) {
        const renovacao = await db.query(
          `
          SELECT 1
          FROM pagamentos
          WHERE email = $1
          AND telefone = $2
          AND status = $3
          AND criado_em >= $4
          LIMIT 1
          `,
          [teste.email, teste.telefone, "confirmado", teste.criado_em]
        );

        liberarCredenciais = renovacao.rows.length > 0;
      }

      const dados = liberarCredenciais
        ? extrairLoginSenha(teste.resposta)
        : { login: "-", senha: "-" };

      lista.push({
        ...teste,
        login: dados.login,
        senha: dados.senha
      });
    }

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
      SET status = $1,
          cancelado_em = NOW(),
          atualizado_em = NOW()
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
