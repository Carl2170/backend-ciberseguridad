const db = require('../config/db.config');

// Crear un nuevo rol (ej: "admin", "user")
const createRole = async (req, res) => {
  const { name } = req.body;

  try {
    const { data, error } = await db
      .from('roles')
      .insert([{ name }])
      .select();

    if (error) throw error;

    res.status(201).json({ message: 'Rol creado', role: data[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear rol' });
  }
};

// Asignar rol a usuario
const assignRole = async (req, res) => {
  const { user_id, role_name } = req.body;

  try {
    // 1. Buscar rol
    const { data: roles, error: errRole } = await db
      .from('roles')
      .select('*')
      .eq('name', role_name);

    if (errRole) throw errRole;
    if (!roles || roles.length === 0) {
      return res.status(404).json({ message: 'Rol no encontrado' });
    }

    const role = roles[0];

    // 2. Asignar rol al usuario
    const { error: errAssign } = await db
      .from('user_roles')
      .insert([{ user_id, role_id: role.id }]);

    if (errAssign) throw errAssign;

    res.json({ message: `Rol "${role_name}" asignado al usuario ${user_id}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al asignar rol' });
  }
};


// (Opcional) Obtener roles de un usuario
const getUserRoles = async (req, res) => {
  const { user_id } = req.params;

  try {
    const { data, error } = await db
      .from('user_roles')
      .select('roles(name)')
      .eq('user_id', user_id);

    if (error) throw error;

    const roles = data.map(r => r.roles.name);

    res.json({ user_id, roles });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener roles del usuario' });
  }
};

module.exports = {
  createRole,
  assignRole,
  getUserRoles
};
