<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>NEXBIT SAFE | QR Sync</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>

<style>
body{
  margin:0;
  height:100vh;
  background:#050b13;
  display:flex;
  align-items:center;
  justify-content:center;
  color:#e6f1ff;
  font-family:Arial;
}
.card{
  width:360px;
  background:#0b1624;
  border-radius:16px;
  padding:24px;
  text-align:center;
}
.qr img{width:220px;height:220px}
.status{color:#00d084;display:none}
</style>
</head>

<body>
<div class="card">
  <h3>Scan to Sync</h3>
  <div class="qr"><img id="qrImg"></div>
  <div class="status" id="ok">✔ Connected</div>
</div>

<script>
/* ===============================
   主业务 API
================================ */
const MAIN_API = "https://crypto-management-production-5e04.up.railway.app";

/* ===============================
   生成 / 读取 uid（无登录）
================================ */
let uid = localStorage.getItem("uid");
if (!uid) {
  uid = "session_" + crypto.randomUUID();
  localStorage.setItem("uid", uid);
}

/* ===============================
   创建二维码
================================ */
let token = null;

async function createQR(){
  const res = await fetch("/api/qr/create");
  const data = await res.json();
  token = data.token;
  document.getElementById("qrImg").src = data.qr;
  poll();
}

/* ===============================
   轮询扫码状态
================================ */
function poll(){
  const t = setInterval(async ()=>{
    const res = await fetch("/api/qr/status?token=" + token);
    const data = await res.json();

    if (data.status === "success" && data.uid) {
      clearInterval(t);

      localStorage.setItem("uid", data.uid);
      document.getElementById("ok").style.display = "block";

      connectMain(data.uid);
    }
  }, 1200);
}

/* ===============================
   对接主业务余额 + SSE
================================ */
async function connectMain(uid){
  const r = await fetch(`${MAIN_API}/api/balance/${uid}`);
  const j = await r.json();
  console.log("Balance:", j.balance);

  const es = new EventSource(`${MAIN_API}/wallet/${uid}/sse`);
  es.addEventListener("balance", e=>{
    console.log("Realtime:", JSON.parse(e.data));
  });
}

createQR();
</script>
</body>
</html>
