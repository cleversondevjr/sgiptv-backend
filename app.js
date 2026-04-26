import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { MercadoPagoConfig, Payment } from "mercadopago";
import { db } from "./db.js";

const app = express();

app.use(cors());
app.use(express.json());

const client = new MercadoPagoConfig({
  accessToken: process.env.ACCESS_TOKEN
});

const JWT_SECRET = process.env.JWT_SECRET || "sgiptv_admin_secret";

const TESTE_URLS = {
  iptv_com_adulto: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/BV4D3rLaqZ",
  iptv_sem_adulto: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/8241Kg1mxd",
  p2p: "https://prpainel.online/api/chatbot/ywDm7Eb1pR/B0VDVALK3q"
};

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

app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  if (
    usuario === process.env.ADMIN_USER &&
    senha === process.env.ADMIN_PASS
  ) {
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

app.post("/pix", async (req, res) => {
  const { plano, valor, email, telefone } = req.body;

  if (!valor || !email || !telefone) {
    return res.status(400).json({
      error: "Informe plano, valor, email e WhatsApp."
    });
  }

  try {
    const payment = new Payment(client);

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano || "Plano SG IPTV",
        payment_method_id: "pix",
        payer: {
          email
        },
        notification_url: "https://sgiptv-backend.onrender.com/webhook"
      }
    });

    const paymentId = String(result.id);

    try {
      await db.query(
        "INSERT INTO pagamentos (email, telefone, plano, valor, status, payment_id) VALUES ($1, $2, $3, $4, $5, $6)",
        [email, telefone, plano || "Plano SG IPTV", valor, "pendente", paymentId]
      );
    } catch (dbError) {
      console.error("Erro ao salvar telefone. Tentando salvar sem telefone:", dbError.message);

      await db.query(
        "INSERT INTO pagamentos (email, plano, valor, status, payment_id) VALUES ($1, $2, $3, $4, $5)",
        [email, plano || "Plano SG IPTV", valor, "pendente", paymentId]
      );
    }

    const data = result.point_of_interaction.transaction_data;

    res.json({
      qr_code: data.qr_code,
      qr_base64: data.qr_code_base64
    });

  } catch (error) {
    console.error("Erro PIX:", error);

    res.status(500).json({
      error: "Erro ao gerar Pix"
    });
  }
});

app.get("/pagamentos", verificarToken, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM pagamentos ORDER BY id DESC");
    res.json(result.rows);
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

    if (!paymentId) {
      return res.sendStatus(200);
    }

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

app.post("/teste-iptv", async (req, res) => {
  let { email, telefone, tipoTeste } = req.body;

  if (!email || !telefone) {
    return res.status(400).json({
      error: "Informe email e WhatsApp para gerar o teste."
    });
  }

  email = String(email).trim().toLowerCase();
  telefone = String(telefone).replace(/\D/g, "");
  tipoTeste = tipoTeste || "iptv_com_adulto";

  const EMAILS_LIBERADOS = [
    "suportesgiptv01@gmail.com",
    "cleversonleite2014@gmail.com"
  ];

  const TELEFONES_LIBERADOS = [
    "11919628194",
    "11951623333"
  ];

  const liberadoParaTeste =
    EMAILS_LIBERADOS.includes(email) ||
    TELEFONES_LIBERADOS.includes(telefone);

  try {
    if (!liberadoParaTeste) {
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
      headers: {
        "Content-Type": "application/json"
      },
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

    await db.query(
      `
      INSERT INTO testes_iptv (email, telefone, resposta)
      VALUES ($1, $2, $3)
      ON CONFLICT DO NOTHING
      `,
      [email, telefone, textoFormatado]
    );

    let emailEnviado = false;

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
          }
        });

        await transporter.sendMail({
          from: `"SG IPTV" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: "Seu teste grátis SG IPTV",
          text: textoFormatado,
          html: `
            <div style="font-family: Arial, sans-serif; background:#05000f; color:#ffffff; padding:25px;">
              <div style="max-width:760px; margin:auto; background:#0b0018; border:1px solid #7e22ce; border-radius:14px; padding:25px;">
                <h2 style="color:#facc15; margin-top:0;">Seu teste grátis SG IPTV foi gerado!</h2>

                <pre style="
                  white-space:pre-wrap;
                  word-wrap:break-word;
                  background:#020617;
                  color:#ffffff;
                  border:1px solid #7e22ce;
                  border-radius:12px;
                  padding:18px;
                  font-size:14px;
                  line-height:1.6;
                ">${textoFormatado}</pre>

                <p style="color:#facc15; font-weight:bold;">
                  Equipe SG IPTV
                </p>
              </div>
            </div>
          `
        });

        emailEnviado = true;

      } catch (emailError) {
        console.error("Erro ao enviar email, mas teste foi gerado:", emailError);
      }
    }

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

    res.status(500).json({
      error: "Erro ao gerar teste IPTV."
    });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log("🚀 Backend rodando na porta", PORT);
});