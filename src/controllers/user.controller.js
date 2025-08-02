// src/controllers/user.controller.js

const User = require('../models/user.model');

const getProfile = async (req, res) => {
  try {
    // req.userId viene del middleware de autenticación
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    return res.json({ id: user.id, email: user.email, createdAt: user.createdAt });
  } catch (error) {
    return res.status(500).json({ message: 'Error en el servidor' });
  }
};

const updateProfile = async (req, res) => {
  try {
    const updates = req.body;
    const updatedUser = await User.update(req.userId, updates);

    return res.json({ message: 'Perfil actualizado', user: updatedUser });
  } catch (error) {
    return res.status(500).json({ message: 'Error en el servidor' });
  }
};

module.exports = {
  getProfile,
  updateProfile
};
