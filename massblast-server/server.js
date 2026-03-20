const express  = require('express');
const cors     = require('cors');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════
// БАЗА ДАННЫХ (JSON файл)
// ══════════════════════════════════════
const DB_FILE = path.join(__dirname, 'db.json');

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return { users: {}, keys: {}, emails: {} };
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch { return { users: {}, keys: {}, emails: {} }; }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ══════════════════════════════════════
// УТИЛИТЫ
// ══════════════════════════════════════
function hashPass(s) {
  return crypto.createHash('sha256').update(s + 'massblast_salt').digest('hex');
}

function genUID() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function subStatus(expiry) {
  if (!expiry) return false;
  return Date.now() < expiry;
}

// ══════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════

// Регистрация
app.post('/api/register', (req, res) => {
  const { login, pass } = req.body;
  if (!login || !pass) return res.status(400).json({ error: 'Нет логина или пароля' });
  if (login.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (pass.length < 6)  return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const db = readDB();
  if (db.users[login]) return res.status(400).json({ error: 'Логин уже занят' });

  const uid = genUID();
  db.users[login] = { id: uid, passHash: hashPass(pass), subExpiry: null };
  writeDB(db);
  res.json({ ok: true, uid });
});

// Вход
app.post('/api/login', (req, res) => {
  const { login, pass } = req.body;
  const db = readDB();
  const u  = db.users[login];
  if (!u) return res.status(401).json({ error: 'Пользователь не найден' });
  if (u.passHash !== hashPass(pass)) return res.status(401).json({ error: 'Неверный пароль' });

  const active = subStatus(u.subExpiry);
  res.json({ ok: true, uid: u.id, subExpiry: u.subExpiry, subActive: active, isAdmin: !!u.isAdmin });
});

// Активация ключа
app.post('/api/activate', (req, res) => {
  const { login, key } = req.body;
  const db  = readDB();
  const u   = db.users[login];
  if (!u)  return res.status(404).json({ error: 'Пользователь не найден' });

  const kd = db.keys[key.toUpperCase()];
  if (!kd) return res.status(404).json({ error: 'Ключ не найден' });
  if (kd.usedBy) return res.status(400).json({ error: 'Ключ уже использован' });

  const now  = Date.now();
  const base = (u.subExpiry && u.subExpiry > now) ? u.subExpiry : now;
  u.subExpiry  = base + kd.days * 86400000;
  kd.usedBy    = u.id;
  writeDB(db);

  res.json({ ok: true, subExpiry: u.subExpiry });
});

// Получить статус пользователя
app.post('/api/status', (req, res) => {
  const { login } = req.body;
  const db = readDB();
  const u  = db.users[login];
  if (!u)  return res.status(404).json({ error: 'Не найден' });
  res.json({ subExpiry: u.subExpiry, subActive: subStatus(u.subExpiry), uid: u.id, isAdmin: !!u.isAdmin });
});

// ══════════════════════════════════════
// EMAIL STORAGE ROUTES
// ══════════════════════════════════════

// Сохранить почты пользователя
app.post('/api/emails/save', (req, res) => {
  const { login, pass, emails } = req.body;
  const db = readDB();
  const u  = db.users[login];
  if (!u || u.passHash !== hashPass(pass)) return res.status(401).json({ error: 'Не авторизован' });
  if (!subStatus(u.subExpiry)) return res.status(403).json({ error: 'Нет подписки' });

  db.emails[u.id] = emails; // [{email, pass}]
  writeDB(db);
  res.json({ ok: true });
});

// Получить почты пользователя
app.post('/api/emails/get', (req, res) => {
  const { login, pass } = req.body;
  const db = readDB();
  const u  = db.users[login];
  if (!u || u.passHash !== hashPass(pass)) return res.status(401).json({ error: 'Не авторизован' });
  if (!subStatus(u.subExpiry)) return res.status(403).json({ error: 'Нет подписки' });

  res.json({ emails: db.emails[u.id] || [] });
});

// ══════════════════════════════════════
// ОТПРАВКА ПИСЬМА
// ══════════════════════════════════════
app.post('/api/send', async (req, res) => {
  const { login, pass, from, fromPass, fromName, to, subject, body } = req.body;

  // Проверяем подписку
  const db = readDB();
  const u  = db.users[login];
  if (!u || u.passHash !== hashPass(pass)) return res.status(401).json({ error: 'Не авторизован' });
  if (!subStatus(u.subExpiry)) return res.status(403).json({ error: 'Подписка истекла' });

  const RESEND_KEY = process.env.RESEND_API_KEY || 're_ZBmtsfjN_2JivUNqs6zKdiv5QWNvYZTr3';

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RESEND_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'MassBlast <onboarding@resend.dev>',
        to: [to],
        subject,
        text: body,
        reply_to: from
      })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.message || 'Resend error');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════
// ADMIN ROUTES (защищены паролем)
// ══════════════════════════════════════
const ADMIN_PASS    = process.env.ADMIN_PASSWORD || 'sasha2009030509';
const ADMIN_LOGIN   = 'stmp';
const ADMIN_HASH    = require('crypto').createHash('sha256').update('sasha2009030509' + 'massblast_salt').digest('hex');

// Создаём аккаунт админа при старте если его нет
function ensureAdminAccount() {
  const db = readDB();
  if (!db.users[ADMIN_LOGIN]) {
    db.users[ADMIN_LOGIN] = {
      id: 'admin_' + ADMIN_LOGIN,
      passHash: ADMIN_HASH,
      subExpiry: 9999999999999, // бессрочно
      isAdmin: true
    };
    writeDB(db);
    console.log('Создан аккаунт администратора:', ADMIN_LOGIN);
  }
}
ensureAdminAccount();

function checkAdmin(req, res) {
  const { adminPass, login, pass } = req.body;
  // Обычная проверка по паролю
  if (adminPass === ADMIN_PASS) return true;
  // Или проверка: пользователь сам является админом
  if (login && pass) {
    const db = readDB();
    const u  = db.users[login];
    if (u && u.passHash === hashPass(pass) && u.isAdmin) return true;
  }
  res.status(403).json({ error: 'Нет доступа' }); return false;
}

// Создать ключ
app.post('/api/admin/genkey', (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { days } = req.body;
  const seg = () => Math.random().toString(36).slice(2,6).toUpperCase();
  const key = seg()+'-'+seg()+'-'+seg()+'-'+seg();
  const db  = readDB();
  db.keys[key] = { days: days||30, createdAt: Date.now(), usedBy: null };
  writeDB(db);
  res.json({ ok: true, key });
});

// Список ключей
app.post('/api/admin/keys', (req, res) => {
  if (!checkAdmin(req, res)) return;
  const db = readDB();
  res.json({ keys: db.keys });
});

// Список пользователей
app.post('/api/admin/users', (req, res) => {
  if (!checkAdmin(req, res)) return;
  const db = readDB();
  const users = {};
  for (const [login, u] of Object.entries(db.users)) {
    users[login] = { id: u.id, subExpiry: u.subExpiry, subActive: subStatus(u.subExpiry) };
  }
  res.json({ users });
});

// Продлить подписку
app.post('/api/admin/extend', (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { uid, days } = req.body;
  const db    = readDB();
  const entry = Object.entries(db.users).find(([,u]) => u.id === uid);
  if (!entry) return res.status(404).json({ error: 'Не найден' });
  const [, u] = entry;
  const now   = Date.now();
  u.subExpiry = ((u.subExpiry && u.subExpiry > now) ? u.subExpiry : now) + days * 86400000;
  writeDB(db);
  res.json({ ok: true, subExpiry: u.subExpiry });
});

// Заблокировать
app.post('/api/admin/revoke', (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { uid } = req.body;
  const db = readDB();
  const entry = Object.entries(db.users).find(([,u]) => u.id === uid);
  if (!entry) return res.status(404).json({ error: 'Не найден' });
  entry[1].subExpiry = 0;
  writeDB(db);
  res.json({ ok: true });
});

// Fallback — отдаём index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log('MassBlast сервер запущен на порту ' + PORT));
