const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_bridgework';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Локальна база даних у JSON-файлі (для простоти)
const DB_FILE = path.join(__dirname, 'database.json');

function readData() {
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      users: [
        {
          id: 1,
          email: "admin@bridgework.com",
          passwordHash: bcrypt.hashSync("Admin123!", 10),
          role: "admin",
          name: "System Administrator"
        }
      ],
      tasks: [
        { id: 101, userId: 2, title: "Завантажити довідку про несудимість", status: "pending", dueDate: "2026-09-20" }
      ],
      dossiers: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function writeData(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Middleware для перевірки авторизації
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Необхідна авторизація" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Токен недійсний" });
    req.user = user;
    next();
  });
}

// === API ЕНДПОЙНТИ ===

// 1. Реєстрація клієнта
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: "Усі поля обов'язкові" });
  }

  const db = readData();
  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ error: "Користувач з таким Email вже існує" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now(),
    name,
    email,
    passwordHash: hashedPassword,
    role: "client"
  };

  db.users.push(newUser);
  writeData(db);

  res.json({ message: "Реєстрація успішна! Тепер увійдіть." });
});

// 2. Вхід (Логін)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db = readData();
  const user = db.users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Невірний email або пароль" });
  }

  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, role: user.role, name: user.name });
});

// 3. Отримання завдань клієнта
app.get('/api/client/tasks', authenticateToken, (req, res) => {
  const db = readData();
  const userTasks = db.tasks.filter(t => t.userId === req.user.id);
  res.json(userTasks);
});

// 4. Панель Адміна: Отримати всіх користувачів та всі завдання
app.get('/api/admin/dashboard', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Доступ заборонено. Потрібні права адміна." });
  }
  const db = readData();
  res.json({
    users: db.users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })),
    tasks: db.tasks
  });
});

// 5. Адмін додає завдання клієнту
app.post('/api/admin/tasks', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Доступ заборонено" });
  }
  const { userId, title, dueDate } = req.body;
  const db = readData();

  const newTask = {
    id: Date.now(),
    userId: Number(userId),
    title,
    status: 'pending',
    dueDate
  };

  db.tasks.push(newTask);
  writeData(db);
  res.json({ message: "Завдання успішно призначено клієнту", task: newTask });
});

app.listen(PORT, () => {
  console.log(`Сервер працює на порту ${PORT}`);
});
