// backend/server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

// ใช้ PORT จาก env ถ้าไม่มีให้ใช้ 3000
const PORT = process.env.PORT || 3000;
// ใช้ SECRET จาก env ถ้าไม่มีให้ใช้ค่า default (แนะนำให้ตั้งเองเวลาออนไลน์)
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_TO_YOUR_OWN_SECRET_123456";

// ----- Middleware CORS แบบ manual ให้ทุก request -----
app.use((req, res, next) => {
  console.log("CORS middleware:", req.method, req.path); // ให้ดูใน log บน Render ได้

  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // ถ้าเป็น preflight (OPTIONS) ตอบกลับเลย
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());

// ----- Database -----
const dbPath = path.join(__dirname, "lotto.db");
const db = new sqlite3.Database(dbPath);

// สร้างตารางถ้ายังไม่มี
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS histories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      mode TEXT NOT NULL,
      top_digits_mode INTEGER NOT NULL,
      config_json TEXT NOT NULL,
      summary_html TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// ----- Helper: สร้าง JWT Token -----
function createToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ----- Middleware ตรวจ Token -----
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }
  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ===================== AUTH =====================

// สมัครสมาชิก
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "กรุณากรอกอีเมลและรหัสผ่าน" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();

    db.run(
      "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
      [email, passwordHash, createdAt],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "อีเมลนี้มีผู้ใช้งานแล้ว" });
          }
          console.error("Register error:", err);
          return res.status(500).json({ error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
        }

        const user = { id: this.lastID, email };
        const token = createToken(user);
        return res.json({
          message: "สมัครสมาชิกสำเร็จ",
          token,
          user: { id: user.id, email: user.email }
        });
      }
    );
  } catch (err) {
    console.error("Register hash error:", err);
    res.status(500).json({ error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// เข้าสู่ระบบ
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "กรุณากรอกอีเมลและรหัสผ่าน" });
  }

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, row) => {
      if (err) {
        console.error("Login query error:", err);
        return res.status(500).json({ error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
      }
      if (!row) {
        return res.status(400).json({ error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
      }

      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) {
        return res.status(400).json({ error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
      }

      const user = { id: row.id, email: row.email };
      const token = createToken(user);
      return res.json({
        message: "เข้าสู่ระบบสำเร็จ",
        token,
        user: { id: user.id, email: user.email }
      });
    }
  );
});

// ข้อมูลผู้ใช้ปัจจุบัน
app.get("/api/me", authMiddleware, (req, res) => {
  db.get(
    "SELECT id, email, created_at FROM users WHERE id = ?",
    [req.userId],
    (err, row) => {
      if (err) {
        console.error("Me error:", err);
        return res.status(500).json({ error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
      }
      if (!row) {
        return res.status(404).json({ error: "ไม่พบผู้ใช้" });
      }
      res.json({ user: row });
    }
  );
});

// ===================== HISTORIES =====================

// บันทึกประวัติ
app.post("/api/histories", authMiddleware, (req, res) => {
  const {
    mode,
    topDigitsMode,
    historyTop,
    historyBottom,
    useLastN,
    weightMode,
    summaryHtml
  } = req.body || {};

  if (!mode || !topDigitsMode || !historyTop) {
    return res.status(400).json({ error: "ข้อมูลไม่ครบ mode / topDigitsMode / historyTop" });
  }

  const config = {
    mode,
    topDigitsMode,
    historyTop,
    historyBottom,
    useLastN,
    weightMode
  };

  const createdAt = new Date().toISOString();

  db.run(
    `INSERT INTO histories (user_id, mode, top_digits_mode, config_json, summary_html, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [req.userId, mode, topDigitsMode, JSON.stringify(config), summaryHtml || "", createdAt],
    function (err) {
      if (err) {
        console.error("Insert history error:", err);
        return res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึกประวัติ" });
      }
      return res.json({
        message: "บันทึกประวัติสำเร็จ",
        historyId: this.lastID
      });
    }
  );
});

// ดึงประวัติ (ล่าสุด 20 รายการ)
app.get("/api/histories", authMiddleware, (req, res) => {
  db.all(
    `SELECT id, mode, top_digits_mode, config_json, summary_html, created_at
     FROM histories
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 20`,
    [req.userId],
    (err, rows) => {
      if (err) {
        console.error("Select histories error:", err);
        return res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลประวัติ" });
      }
      res.json({ histories: rows });
    }
  );
});

// Root test
app.get("/", (req, res) => {
  res.json({ status: "Lotto backend OK" });
});
// Root test
app.get("/", (req, res) => {
  res.json({ status: "Lotto backend OK" });
});

app.listen(PORT, () => {
  console.log(`Lotto backend server running on http://localhost:${PORT}`);
});

