require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Настройка БД
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors());
app.use(express.json());

// 🔐 Проверка токена (middleware)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Токен не предоставлен' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.user = user;
    next();
  });
};

// 📍 ЭНДПОИНТЫ

// 1. Регистрация первого админа (одноразовый)
app.post('/api/init-admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Проверяем, есть ли уже админ
    const checkAdmin = await pool.query("SELECT * FROM users WHERE role = 'admin'");
    if (checkAdmin.rows.length > 0) {
      return res.status(400).json({ error: 'Администратор уже существует' });
    }
    
    // Хешируем пароль
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Создаем админа
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, passwordHash, 'admin']
    );
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка создания администратора' });
  }
});

// 2. Вход (логин)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Ищем пользователя
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }
    
    const user = result.rows[0];
    
    // Проверяем пароль
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }
    
    // Создаем токен
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

// 3. Проверка токена
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// 4. Создание нового пользователя (только для админа)
app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    // Проверяем, что это админ
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    const { username, password, role } = req.body;
    
    // Хешируем пароль
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Создаем пользователя
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, created_at',
      [username, passwordHash, role || 'user']
    );
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') { // Duplicate username
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }
    console.error(error);
    res.status(500).json({ error: 'Ошибка создания пользователя' });
  }
});

// 5. Получить всех пользователей (только для админа)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка получения пользователей' });
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`API запущен на порту ${port}`);
});