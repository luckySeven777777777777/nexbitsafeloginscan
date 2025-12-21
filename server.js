import express from "express";
import cors from "cors";
import QRCode from "qrcode";
import crypto from "crypto";
import cookieParser from "cookie-parser";

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const tokenMap = new Map();

/* 生成二维码 */
app.get("/api/qr/create", async (req, res) => {
  const token = crypto.randomUUID();

  tokenMap.set(token, {
    status: "pending",
    userId: null
  });

  const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${token}`;
  const qr = await QRCode.toDataURL(scanUrl);

  res.json({ token, qr });
});

/* 电脑轮询状态 */
app.get("/api/qr/status", (req, res) => {
  const { token } = req.query;
  const record = tokenMap.get(token);

  if (!record) {
    return res.json({ status: "invalid" });
  }

  res.json({ status: record.status });
});

/* 手机扫码确认（这里是真正登录点） */
app.post("/api/qr/confirm", (req, res) => {
  const { token } = req.body;

  const record = tokenMap.get(token);
  if (!record) {
    return res.status(400).json({ ok: false });
  }

  // 🔥 这里模拟你真实的用户（以后换成真实 userId）
  record.status = "success";
  record.userId = "user_10001";

  res.json({ ok: true });
});

/* 电脑端最终写登录态 */
app.get("/api/qr/finalize", (req, res) => {
  const { token } = req.query;
  const record = tokenMap.get(token);

  if (!record || record.status !== "success") {
    return res.status(401).json({ ok: false });
  }

  // ✅ 真正登录：写 Cookie
  res.cookie("login_user", record.userId, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24
  });

  tokenMap.delete(token);

  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("QR login server running");
});
