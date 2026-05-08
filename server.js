const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const DB_PATH = path.join(__dirname, 'users.db');

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Erro ao abrir o banco de dados SQLite:', err.message);
    process.exit(1);
  }
  console.log('Banco de dados SQLite conectado em', DB_PATH);
});

const createTableSql = `
CREATE TABLE IF NOT EXISTS cadastros (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  senha TEXT NOT NULL,
  username TEXT NOT NULL
);
`;

db.run(createTableSql, (err) => {
  if (err) {
    console.error('Erro ao criar tabela de usuários:', err.message);
    process.exit(1);
  }
});

app.post('/register', (req, res) => {
  const { email, senha, username } = req.body;

  if (!email || !senha || !username) {
    return res.status(400).json({ error: 'email, senha e username são obrigatórios.' });
  }

  const insertSql = 'INSERT INTO users (email, senha, username) VALUES (?, ?, ?)';
  db.run(insertSql, [email, senha, username], function (err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(409).json({ error: 'Este email já está cadastrado.' });
      }
      console.error('Erro ao inserir usuário:', err);
      return res.status(500).json({ error: 'Erro ao salvar usuário no banco de dados.' });
    }

    res.status(201).json({ message: 'Cadastro realizado com sucesso.', userId: this.lastID });
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
