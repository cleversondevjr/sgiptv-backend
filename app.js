import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { db } from "./db.js";

import pkg from "mercadopago";
const { MercadoPagoConfig, Payment } = pkg;

const app = express();

app.use(cors());
app.use(express.json());

const client = new MercadoPagoConfig({
  accessToken: process.env.ACCESS_TOKEN
});

const JWT_SECRET = process.env.JWT_SECRET || "sgiptv_admin_secret";

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
  const { plano, valor, email } = req.body;

  try {
    const payment = new Payment(client);

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano,
        payment_method_id: "pix",
        payer: { email },
        notification_url: "https://sgiptv-backend.onrender.com/webhook"
      }
    });

    await db.query(
      "INSERT INTO pagamentos (email, plano, valor, status, payment_id) VALUES ($1,$2,$3,$4,$5)",
      [email, plano, valor, "pendente", String(result.id)]
    );

    res.json({
      qr_code: result.point_of_interaction.transaction_data.qr_code,
      qr_base64: result.point_of_interaction.transaction_data.qr_code_base64
    });

  } catch (error) {
    console.error("Erro ao gerar Pix:", error);
    res.status(500).json({ error: "Erro ao gerar Pix" });
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
    }

    res.sendStatus(200);

  } catch (error) {
    console.error("Erro webhook:", error);
    res.sendStatus(500);
  }
});

app.post("/teste-iptv", async (req, res) => {
  const { email, telefone } = req.body;

  const EMAIL_LIBERADO = "cleversonleite2014@gmail.com";
  const TELEFONE_LIBERADO = "11951623333";

  if (!email || !telefone) {
    return res.status(400).json({
      error: "Email e telefone são obrigatórios."
    });
  }

  try {
    if (email !== EMAIL_LIBERADO && telefone !== TELEFONE_LIBERADO) {
      const jaExiste = await db.query(
        "SELECT * FROM testes_iptv WHERE email = $1 OR telefone = $2",
        [email, telefone]
      );

      if (jaExiste.rows.length > 0) {
        return res.status(409).json({
          error: "Este email ou telefone já solicitou um teste grátis."
        });
      }
    }

    const respostaApi = await fetch(process.env.TESTE_IPTV_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email, telefone })
    });

    const texto = await respostaApi.text();

    await db.query(
      "INSERT INTO testes_iptv (email, telefone, resposta) VALUES ($1,$2,$3)",
      [email, telefone, texto]
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
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Seu teste grátis SG IPTV",
          html: `
            <h2>Seu teste grátis SG IPTV foi gerado!</h2>
            <p>As configurações completas estão abaixo:</p>
            <pre>${texto}</pre>
            <p>Equipe SG IPTV</p>
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
        : "Teste gerado. Email não enviado, verifique as configurações.",
      resposta: texto,
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
