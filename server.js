import express from "express";
import cors from "cors";
import QRCode from "qrcode";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";

const app = express();

/* ===============================
   基础中间件
================================ */
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

/* ===============================
   修复 ESM 下的 __dirname
================================ */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ===============================
   静态文件（login.html / scan.html）
================================ */
app.use(express.static(__dirname));

/* ===============================
   明确页面路由（关键！）
================================ */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/scan.html", (req, res) => {
  res.sendFile(path.join(__dirname, "scan.html"));
});

/* ===============================
   内存 token（测试阶段 OK）
================================ */
const tokenMap = new Map();

/* ===============================
   1️⃣ 生成二维码
================================ */
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

/* ===============================
   2️⃣ 电脑轮询状态
================================ */
app.get("/api/qr/status", (req, res) => {
  const { token } = req.query;
  const record = tokenMap.get(token);

  if (!record) {
    return res.json({ status: "invalid" });
  }

  res.json({ status: record.status });
});

/* ===============================
   3️⃣ 手机扫码确认（登录）
================================ */
app.post("/api/qr/confirm", (req, res) => {
  const { token } = req.body;

  const record = tokenMap.get(token);
  if (!record) {
    return res.status(400).json({ ok: false });
  }

  // 🔥 这里以后换成你真实用户系统
  record.status = "success";
  record.userId = "user_10001";

  res.json({ ok: true });
});

/* ===============================
   4️⃣ 电脑端最终登录（写 Cookie）
================================ */
app.get("/api/qr/finalize", (req, res) => {
  const { token } = req.query;
  const record = tokenMap.get(token);

  if (!record || record.status !== "success") {
    return res.status(401).json({ ok: false });
  }

  res.cookie("login_user", record.userId, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24
  });

  tokenMap.delete(token);

  res.json({ ok: true });
});

/* ===============================
   启动服务（Railway）
================================ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("✅ QR login server running on port", PORT);
});
