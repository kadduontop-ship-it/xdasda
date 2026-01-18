import express from "express";
import sqlite3 from "sqlite3";
import fetch from "node-fetch";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const db = new sqlite3.Database("./database.db");
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const FALCON_API_KEY = process.env.FALCON_API_KEY;

/* ================= DATABASE ================= */

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS cooldowns (
  key TEXT,
  platform TEXT,
  last_used INTEGER
)
`);

/* ================= AUTH ================= */

app.post("/api/signup", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  db.run(
    "INSERT INTO users (email,password) VALUES (?,?)",
    [req.body.email, hash],
    err => {
      if (err) return res.json({ error: "Email exists" });
      res.json({ success: true });
    }
  );
});

app.post("/api/login", (req, res) => {
  db.get(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    async (err, user) => {
      if (!user) return res.json({ error: "Invalid" });
      const ok = await bcrypt.compare(req.body.password, user.password);
      if (!ok) return res.json({ error: "Invalid" });

      const token = jwt.sign({ id: user.id }, JWT_SECRET);
      res.json({ token });
    }
  );
});

/* ================= ORDER ================= */

app.post("/api/order", async (req, res) => {
  const { platform, link, token } = req.body;

  let key;
  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      key = "user_" + user.id;
    } catch {
      return res.json({ error: "Invalid token" });
    }
  } else {
    key = "ip_" + req.ip;
  }

  const now = Date.now();
  const cooldown = 15 * 60 * 1000;

  db.get(
    "SELECT last_used FROM cooldowns WHERE key=? AND platform=?",
    [key, platform],
    async (err, row) => {
      if (row && now - row.last_used < cooldown) {
        return res.json({ error: "Cooldown active" });
      }

      const service =
        platform === "tiktok" ? 2409 :
        platform === "instagram" ? 2851 : null;

      if (!service) return res.json({ error: "Invalid platform" });

      const r = await fetch("https://falconsmmpanel.com/api/v2", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          key: FALCON_API_KEY,
          action: "add",
          service,
          link,
          quantity: 100
        })
      });

      const d = await r.json();
      if (!d.order) return res.json({ error: "Order failed" });

      db.run(
        "REPLACE INTO cooldowns VALUES (?,?,?)",
        [key, platform, now]
      );

      res.json({ success: true });
    }
  );
});

app.listen(PORT, () =>
  console.log("Running on http://localhost:" + PORT)
);
