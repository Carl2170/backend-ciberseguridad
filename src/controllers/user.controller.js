const db = require('../config/db.config');

const getProfile = async (req, res) => {
  try {
    const { data: user, error } = await db
      .from('users')
      .select('id, email, full_name, created_at')
      .eq('id', req.userId)
      .single();

    if (error) throw error;
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    return res.json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
};

const updateProfile = async (req, res) => {
  try {
    const updates = req.body;

    const { data: updatedUser, error } = await db
      .from('users')
      .update(updates)
      .eq('id', req.userId)
      .select('id, email, full_name, created_at')
      .single();

    if (error) throw error;

    return res.json({ message: 'Perfil actualizado', user: updatedUser });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
};

module.exports = {
  getProfile,
  updateProfile
};
