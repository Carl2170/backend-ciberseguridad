const db = require('../config/db.config');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { hashPassword, verifyPassword } = require('../utils/hash');
const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');

const register = async (req, res) => {
  const { email, password, full_name } = req.body;

  try {
    // Verifica si el usuario ya existe
    const { data: existing, error: errExisting } = await db
      .from('users')
      .select('*')
      .eq('email', email);

    if (errExisting) throw errExisting;

    if (existing.length > 0) return res.status(400).json({ message: 'Email ya registrado' });

    const password_hash = await hashPassword(password);

    const { data: [user], error: errInsert } = await db
      .from('users')
      .insert([{ email, password_hash, full_name }])
      .select('id, email, full_name')
      .single();

    if (errInsert) throw errInsert;

    res.status(201).json({ message: 'Usuario registrado con éxito', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error en el registro' });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data: [user], error: errUser } = await db
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (errUser || !user) return res.status(401).json({ message: 'Credenciales inválidas' });

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return res.status(401).json({ message: 'Credenciales inválidas' });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    // Guarda el refresh token
    const { error: errToken } = await db
      .from('refresh_tokens')
      .insert([{
        user_id: user.id,
        token: refreshToken,
        user_agent: req.headers['user-agent'] || 'desconocido',
        ip_address: req.ip,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 días en ms
      }]);

    if (errToken) throw errToken;

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
};

const refreshAccessToken = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ message: 'Token requerido' });

  try {
    const { data: [storedToken], error: errToken } = await db
      .from('refresh_tokens')
      .select('*')
      .eq('token', refreshToken)
      .eq('used', false)
      .gt('expires_at', new Date())
      .single();

    if (errToken || !storedToken) return res.status(403).json({ message: 'Token inválido o expirado' });

    // Busca usuario
    const { data: [user], error: errUser } = await db
      .from('users')
      .select('*')
      .eq('id', storedToken.user_id)
      .single();

    if (errUser || !user) return res.status(404).json({ message: 'Usuario no encontrado' });

    const newAccessToken = generateAccessToken(user);

    res.json({ accessToken: newAccessToken });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al refrescar token' });
  }
};

const logout = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ message: 'Token requerido' });

  try {
    const { error } = await db
      .from('refresh_tokens')
      .update({ used: true })
      .eq('token', refreshToken);

    if (error) throw error;

    res.json({ message: 'Sesión cerrada correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al cerrar sesión' });
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const { data: [user], error: errUser } = await db
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (errUser || !user) return res.status(404).json({ msg: 'Usuario no encontrado' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    const { error: errInsert } = await db
      .from('password_reset_tokens')
      .insert([{ user_id: user.id, token, expires_at: expiresAt }]);

    if (errInsert) throw errInsert;

    // Aquí envía correo con el token o link con token
    res.json({ msg: 'Token generado', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al generar token' });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const { data: [resetToken], error: errToken } = await db
      .from('password_reset_tokens')
      .select('*')
      .eq('token', token)
      .eq('used', false)
      .gt('expires_at', new Date())
      .single();

    if (errToken || !resetToken) return res.status(400).json({ msg: 'Token inválido o expirado' });

    const hashed = await bcrypt.hash(newPassword, 10);

    const { error: errUpdateUser } = await db
      .from('users')
      .update({ password_hash: hashed })
      .eq('id', resetToken.user_id);

    if (errUpdateUser) throw errUpdateUser;

    const { error: errUsed } = await db
      .from('password_reset_tokens')
      .update({ used: true })
      .eq('token', token);

    if (errUsed) throw errUsed;

    res.json({ msg: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Error al actualizar la contraseña' });
  }
};

module.exports = { 
  register, 
  login, 
  refreshAccessToken, 
  logout, 
  forgotPassword, 
  resetPassword 
};
