import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { db } from "./db.js";

import pkg from "mercadopago";
const { MercadoPagoConfig, Payment } = pkg;

const client = new MercadoPagoConfig({
  accessToken: process.env.ACCESS_TOKEN
});

const app = express();

app.use(cors({
  origin: "*"
}));

app.use(express.json());

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
  console.log("🔥 PIX REAL ATIVO");

  const { plano, valor, email } = req.body;

  try {
    const payment = new Payment(client);

    const result = await payment.create({
      body: {
        transaction_amount: Number(valor),
        description: plano,
        payment_method_id: "pix",
        payer: {
          email: email
        },
        notification_url: "https://sgiptv-backend.onrender.com/webhook"
      }
    });

    await db.query(
      "INSERT INTO pagamentos (email, plano, valor, status, payment_id) VALUES ($1, $2, $3, $4, $5)",
      [email, plano, valor, "pendente", String(result.id)]
    );

    console.log("Pagamento gerado e salvo no banco");

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
  console.log("🔔 Webhook recebido:", req.body);

  try {
    const paymentId = req.body?.data?.id;

    if (!paymentId) {
      return res.sendStatus(200);
    }

    const payment = new Payment(client);
    const result = await payment.get({ id: paymentId });

    console.log("Status Mercado Pago:", result.status);

    if (result.status === "approved") {
      await db.query(
        "UPDATE pagamentos SET status = $1 WHERE payment_id = $2",
        ["confirmado", String(paymentId)]
      );

      console.log("✅ Pagamento confirmado automaticamente");
    }

    res.sendStatus(200);

  } catch (error) {
    console.error("Erro no webhook:", error);
    res.sendStatus(500);
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log("🚀 Backend rodando na porta", PORT);
});