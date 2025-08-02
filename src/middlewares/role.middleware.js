const db = require('../config/db.config');

// Middleware para verificar rol
const verifyRole = (roleName) => {
  return async (req, res, next) => {
    const userId = req.user.id;

    const roles = await db`
      SELECT r.name FROM roles r
      JOIN user_roles ur ON ur.role_id = r.id
      WHERE ur.user_id = ${userId}
    `;

    const hasRole = roles.some(r => r.name === roleName);

    if (!hasRole) return res.status(403).json({ msg: 'No autorizado' });

    next();
  };
};

module.exports = verifyRole;
