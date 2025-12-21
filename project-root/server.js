import express from "express";
import cors from "cors";
import QRCode from "qrcode";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());
app.use(express.json());

// ===== ESModule 兼容 =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== 静态文件 =====
app.use(express.static(path.join(__dirname, "public")));

// ===== 内存 token 池 =====
/*
tokenMap:
token => {
  status: "pending" | "success",
  createdAt: number
}
*/
const tokenMap = new Map();

// ===== 创建二维码 =====
app.get("/api/qr/create", async (req, res) => {
  const token = Math.random().toString(36).slice(2) + Date.now();

  tokenMap.set(token, {
    status: "pending",
    createdAt: Date.now()
  });

  const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${token}`;
  const qr = await QRCode.toDataURL(scanUrl);

  res.json({ token, qr });
});

// ===== 查询状态（电脑轮询）=====
app.get("/api/qr/status", (req, res) => {
  const { token } = req.query;
  const record = tokenMap.get(token);

  if (!record) {
    return res.json({ status: "expired" });
  }
  res.json({ status: record.status });
});

// ===== 手机扫码确认 =====
app.post("/api/qr/confirm", (req, res) => {
  const { token } = req.body;
  const record = tokenMap.get(token);

  if (!record) {
    return res.status(400).json({ ok: false });
  }

  record.status = "success";
  res.json({ ok: true });
});

// ===== 自动清理过期 token（5 分钟）=====
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokenMap.entries()) {
    if (now - data.createdAt > 5 * 60 * 1000) {
      tokenMap.delete(token);
    }
  }
}, 60 * 1000);

// ===== 启动 =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("QR login server running on port", PORT);
});
