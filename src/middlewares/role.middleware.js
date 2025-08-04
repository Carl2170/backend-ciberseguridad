const db = require('../config/db.config');

const checkRole = (...rolesAllowed) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?.id;
      if (!userId) return res.status(401).json({ message: 'No autenticado' });

      const { data: userRoles, error } = await db
        .from('user_roles')
        .select('roles(name)')
        .eq('user_id', userId);

      if (error) throw error;

      const rolesNames = userRoles.map(ur => ur.roles.name);

      console.log('Roles del usuario:', rolesNames);

      const hasAccess = rolesAllowed.some(role => rolesNames.includes(role));

      if (!hasAccess) {
        return res.status(403).json({ message: 'Acceso denegado: permisos insuficientes' });
      }

      next();
    } catch (err) {
      console.error('Error en validación de roles:', err);
      res.status(500).json({ message: 'Error en validación de roles' });
    }
  };
};

module.exports = checkRole;
