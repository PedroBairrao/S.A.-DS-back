require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { autenticar } = require('./middleware/auth');

const PORT = process.env.PORT || 3001;
const DB_PATH = path.join(__dirname, 'users.db');
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const BCRYPT_ROUNDS = 10;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET ausente ou curto demais (mínimo 32 caracteres). Configure o arquivo .env.');
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(
  cors({
    origin: (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',').map((o) => o.trim()),
  })
);
app.use(express.json());

// Limita tentativas em rotas sensíveis (contra força bruta)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente em alguns minutos.' },
});

// ---------- Banco de dados ----------
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Erro ao abrir o banco de dados SQLite:', err.message);
    process.exit(1);
  }
  console.log('Banco de dados SQLite conectado em', DB_PATH);
});

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.run(sql, params, function (err) {
      err ? reject(err) : resolve(this);
    })
  );
const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row))));

db.run(
  `CREATE TABLE IF NOT EXISTS cadastros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    username TEXT NOT NULL
  )`,
  (err) => {
    if (err) {
      console.error('Erro ao criar tabela de usuários:', err.message);
      process.exit(1);
    }
  }
);

// ---------- Helpers ----------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Hash falso usado para o tempo de resposta do login não revelar se o email existe
const DUMMY_HASH = bcrypt.hashSync('senha-falsa', BCRYPT_ROUNDS);

function gerarToken(user) {
  return jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: String(user.id),
    expiresIn: JWT_EXPIRES_IN,
  });
}

// ---------- Rotas ----------
app.post('/register', authLimiter, async (req, res) => {
  const { senha } = req.body;
  const email = String(req.body.email || '').trim().toLowerCase();
  const username = String(req.body.username || '').trim();

  if (!email || !senha || !username) {
    return res.status(400).json({ error: 'email, senha e username são obrigatórios.' });
  }
  if (!EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Email inválido.' });
  }
  if (typeof senha !== 'string' || senha.length < 8 || senha.length > 72) {
    return res.status(400).json({ error: 'A senha deve ter entre 8 e 72 caracteres.' });
  }

  try {
    const hash = await bcrypt.hash(senha, BCRYPT_ROUNDS);
    const result = await dbRun('INSERT INTO cadastros (email, senha, username) VALUES (?, ?, ?)', [
      email,
      hash,
      username,
    ]);
    res.status(201).json({ message: 'Cadastro realizado com sucesso.', userId: result.lastID });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Este email já está cadastrado.' });
    }
    console.error('Erro ao inserir usuário:', err);
    res.status(500).json({ error: 'Erro ao salvar usuário no banco de dados.' });
  }
});

app.post('/login', authLimiter, async (req, res) => {
  const { senha } = req.body;
  const email = String(req.body.email || '').trim().toLowerCase();

  if (!email || !senha || typeof senha !== 'string') {
    return res.status(400).json({ error: 'email e senha são obrigatórios.' });
  }

  try {
    const user = await dbGet('SELECT id, email, senha, username FROM cadastros WHERE email = ?', [email]);
    const senhaOk = await bcrypt.compare(senha, user ? user.senha : DUMMY_HASH);

    if (!user || !senhaOk) {
      return res.status(401).json({ error: 'Email ou senha inválidos.' });
    }

    res.json({
      token: gerarToken(user),
      user: { id: user.id, email: user.email, username: user.username },
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: 'Erro ao realizar login.' });
  }
});

// Rota protegida: retorna os dados do usuário logado
app.get('/me', autenticar, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, email, username FROM cadastros WHERE id = ?', [req.user.id]);
    if (!user) return res.status(401).json({ error: 'Usuário não existe mais.' });
    res.json({ user });
  } catch (err) {
    console.error('Erro em /me:', err);
    res.status(500).json({ error: 'Erro ao buscar usuário.' });
  }
});

// Exemplo: para proteger qualquer outra rota, basta colocar "autenticar" antes do handler
// app.get('/avistamentos', autenticar, (req, res) => { ... req.user.id ... });

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
