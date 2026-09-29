const jwt = require('jsonwebtoken');

// Protege rotas: exige o header "Authorization: Bearer <token>"
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Token não informado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.user = { id: Number(payload.sub), email: payload.email, username: payload.username };
    next();
  } catch (err) {
    const error = err.name === 'TokenExpiredError' ? 'Token expirado.' : 'Token inválido.';
    return res.status(401).json({ error });
  }
}

module.exports = { autenticar };
