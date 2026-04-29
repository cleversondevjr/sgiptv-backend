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
  "https://sgiptv-backend.onrender.com/webhook";

const ADMIN_EMAIL_AVISOS = "suportesgiptv01@gmail.com";
const ADMIN_WHATSAPP_AVISOS = "5511919628194";
const ADMIN_PANEL_URL = "https://sgiptv.com.br/admin.html";
const ADMIN_EMAIL_VENCIMENTOS = "suportesgipt01@gmail.com";

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
        const fromEmail = extrairEmailFrom(from) || String(process.env.EMAIL_FROM || "").trim() || null;
        const fromName = extrairNomeFrom(from) || String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();

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

    const fromEmail = String(process.env.EMAIL_FROM || process.env.SMTP_USER || process.env.EMAIL_USER || "").trim();
    const fromName = String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();
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

async function notificarVendaAdmin({ tipo, pagamento, origem }) {
  const p = enriquecerPagamento(pagamento);
  const linhas = [
    `SG IPTV - ${tipo}`,
    "",
    `Plano: ${p.plano}`,
    `Valor: R$ ${p.valor}`,
    `Email: ${p.email}`,
    `WhatsApp cliente: ${p.telefone}`,
    `Payment ID: ${p.payment_id}`,
    origem ? `Origem: ${origem}` : null,
    "",
    `Painel Admin: ${ADMIN_PANEL_URL}`
  ].filter(Boolean);

  const texto = linhas.join("\n");

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

  const fromEmail = String(process.env.EMAIL_FROM || process.env.SMTP_USER || process.env.EMAIL_USER || "").trim();
  const fromName = String(process.env.EMAIL_FROM_NAME || "SG IPTV").trim();
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

  if (!confirmado.notificado_em) {
    await notificarVendaAdmin({ tipo: "Pix recebido", pagamento: confirmado, origem });
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

async function cancelarPagamentosPixExpirados() {
  try {
    await db.query(
      `
      UPDATE pagamentos
      SET status = $1,
          cancelado_em = NOW()
      WHERE status = $2
      AND criado_em <= NOW() - ($3 || ' minutes')::interval
      `,
      ["cancelado", "pendente", PIX_EXPIRACAO_MINUTOS]
    );
  } catch (error) {
    // Se a coluna ainda nao existir (migracao async), faz fallback sem cancelado_em.
    console.error("Erro ao cancelar Pix expirados (com cancelado_em). Tentando fallback:", error);
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
}

async function limparPagamentosCanceladosAntigos() {
  try {
    await db.query(
      `
      DELETE FROM pagamentos
      WHERE status = $1
      AND COALESCE(cancelado_em, atualizado_em, criado_em) <= NOW() - ($2 || ' minutes')::interval
      `,
      ["cancelado", PIX_EXPIRACAO_MINUTOS]
    );
  } catch (error) {
    // Fallback quando cancelado_em ainda nao existe.
    console.error("Erro ao limpar cancelados (com cancelado_em). Tentando fallback:", error);
    await db.query(
      `
      DELETE FROM pagamentos
      WHERE status = $1
      AND criado_em <= NOW() - ($2 || ' minutes')::interval
      `,
      ["cancelado", PIX_EXPIRACAO_MINUTOS]
    );
  }
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

db.query("SELECT NOW()")
  .then(res => console.log("Banco conectado:", res.rows))
  .catch(err => console.error("Erro no banco:", err));

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

db.query(`ALTER TABLE testes_iptv ADD COLUMN IF NOT EXISTS login TEXT`)
  .then(() => console.log("Coluna testes_iptv.login OK"))
  .catch(err => console.error("Erro ao garantir coluna testes_iptv.login:", err));

db.query(`ALTER TABLE testes_iptv ADD COLUMN IF NOT EXISTS senha TEXT`)
  .then(() => console.log("Coluna testes_iptv.senha OK"))
  .catch(err => console.error("Erro ao garantir coluna testes_iptv.senha:", err));

app.get("/", (req, res) => {
  res.send("Backend funcionando 🚀");
});

app.post("/pix", limitePublico, async (req, res) => {
  let { planoId, valor, email, telefone } = req.body;
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
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [email, telefone, plano, valor, "pendente", paymentId]
    );

    const data = result.point_of_interaction.transaction_data;

    await notificarVendaAdmin({
      tipo: "Novo Pix gerado",
      pagamento: { email, telefone, plano, valor, payment_id: paymentId },
      origem: "pix"
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
    res.status(500).json({ error: "Erro ao buscar pagamentos" });
  }
});

app.post("/admin/pix/teste", verificarToken, async (req, res) => {
  let { planoId, valor, email, telefone } = req.body || {};
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
      INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [email, telefone, plano, valor, "pendente", paymentId]
    );

    const data = result.point_of_interaction.transaction_data;

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
      AND criado_em >= $2
      AND criado_em < $3
      ORDER BY criado_em DESC, id DESC
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
    res.status(500).json({ error: "Erro ao buscar pagamentos do mes" });
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
  const { nome, email, telefone } = req.body || {};

  try {
    const result = await db.query(
      `
      UPDATE clientes
      SET nome = $1,
          email = $2,
          telefone = $3,
          atualizado_em = NOW()
      WHERE id = $4
      RETURNING *
      `,
      [
        nome ? String(nome).trim() : null,
        email ? String(email).trim().toLowerCase() : null,
        telefone ? String(telefone).replace(/\\D/g, "") : null,
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
    if (!webhookSecretValido(req)) {
      return res.status(401).json({ error: "Webhook sem autorizacao." });
    }

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
          telefone: cliente.telefone
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

    return res.json({ ok: true });
  } catch (error) {
    console.error("Erro ao enviar emails teste:", error);
    return res.status(500).json({ error: String(error?.message || "Erro ao enviar emails teste.") });
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

    // Garante que todo teste novo apareca tambem na lista de clientes (login/senha).
    try {
      await db.query(
        `
        INSERT INTO clientes (usuario, senha, plano, conexoes, criado_em, vencimento, email, telefone)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (usuario) DO UPDATE SET
          senha = EXCLUDED.senha,
          plano = EXCLUDED.plano,
          conexoes = EXCLUDED.conexoes,
          criado_em = EXCLUDED.criado_em,
          vencimento = EXCLUDED.vencimento,
          email = EXCLUDED.email,
          telefone = EXCLUDED.telefone,
          atualizado_em = NOW()
        `,
        [
          dadosTeste.login,
          dadosTeste.senha,
          "TESTE GRATUITO",
          1,
          agoraIso,
          vencimentoTeste,
          email,
          telefone
        ]
      );
    } catch (clienteError) {
      console.error("Erro ao salvar teste em clientes:", clienteError);
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
