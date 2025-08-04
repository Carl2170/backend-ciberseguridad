const jwt = require('jsonwebtoken');
const db = require('../config/db.config');

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1]?.trim();

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    req.token = token;

    const { data: tokenRecord, error } = await db
      .from('access_tokens')
      .select('*')
      .eq('token', token)
      // .gt('expires_at', new Date())
      .maybeSingle(); // ✅

    if (!tokenRecord) {
      return res.status(403).json({ message: 'Token inválido o expirado (revocado)' });
    }

    next();
  } catch (err) {
    console.error('Error al verificar token:', err.message);
    return res.status(403).json({ message: 'Token inválido' });
  }
};


module.exports = verifyToken;
