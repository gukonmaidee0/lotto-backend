// ----- Middleware -----
// เปิด CORS แบบตอบ preflight ครบ (แก้ CORS ERROR)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // ตอบ Preflight request ของเบราว์เซอร์ (สำคัญสุด)
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();  // << ต้องอยู่ในนี้
});

app.use(express.json());
