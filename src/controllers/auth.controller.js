const db = require('../config/db.config');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { hashPassword, verifyPassword } = require('../utils/hash');
const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');
const { sendPasswordResetEmail } = require('../utils/mailer');

const register = async (req, res) => {
  const { email, password, full_name } = req.body;

  try {
    const { data: existingUser, error: errExisting } = await db
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (errExisting) throw errExisting;
    if (existingUser) return res.status(400).json({ message: 'Email ya registrado' });

    const password_hash = await hashPassword(password);

    const { data: user, error: errInsert } = await db
      .from('users')
      .insert({ email, password_hash, full_name })
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
    const { data: user, error: errUser } = await db
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (errUser || !user) return res.status(401).json({ message: 'Credenciales inválidas' });

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return res.status(401).json({ message: 'Credenciales inválidas' });

    const accessToken = generateAccessToken(user);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // ejemplo: 15 minutos

    await db.from('access_tokens').insert([
      {
        token: accessToken,
        user_id: user.id,
        expires_at: expiresAt
      }
    ]);
    const refreshToken = generateRefreshToken();

    const { error: errToken } = await db
      .from('refresh_tokens')
      .insert({
        user_id: user.id,
        token: refreshToken,
        user_agent: req.headers['user-agent'] || 'desconocido',
        ip_address: req.ip,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });

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
    const { data: storedToken, error: errToken } = await db
      .from('refresh_tokens')
      .select('*')
      .eq('token', refreshToken)
      .eq('used', false)
      .gt('expires_at', new Date())
      .maybeSingle();

    if (errToken || !storedToken) return res.status(403).json({ message: 'Token inválido o expirado' });

    const { data: user, error: errUser } = await db
      .from('users')
      .select('*')
      .eq('id', storedToken.user_id)
      .maybeSingle();

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
  const accessToken = req.token; // viene del middleware

  if (!refreshToken) {
    return res.status(400).json({ message: 'Token requerido' });
  }

  try {
    // Marcar refreshToken como usado
    const { data: updated, error } = await db
      .from('refresh_tokens')
      .update({ used: true })
      .eq('token', refreshToken)
      .select();

    if (error) throw error;

    // Eliminar accessToken actual
    if (accessToken) {
      await db
        .from('access_tokens')
        .delete()
        .eq('token', accessToken);
    }

    res.json({ message: 'Sesión cerrada correctamente' });
  } catch (err) {
    console.error('Error en logout:', err);
    res.status(500).json({ message: 'Error al cerrar sesión' });
  }
};


const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const { data: user, error: errUser } = await db
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (errUser || !user) return res.status(404).json({ msg: 'Usuario no encontrado' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    const { error: errInsert } = await db
      .from('password_reset_tokens')
      .insert({ user_id: user.id, token, expires_at: expiresAt });

    if (errInsert) throw errInsert;

    // Aquí deberías enviar el correo
    await sendPasswordResetEmail(email, token);

    res.json({ msg: 'Token generado y enviado por correo', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al generar token' });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const { data: resetToken, error: errToken } = await db
      .from('password_reset_tokens')
      .select('*')
      .eq('token', token)
      .eq('used', false)
      // .gt('expires_at', new Date())
      .maybeSingle();

    if (errToken || !resetToken) return res.status(400).json({ msg: 'Token inválido o expirado' });

    const hashed = await bcrypt.hash(newPassword, 10);

    const { error: errUpdate } = await db
      .from('users')
      .update({ password_hash: hashed })
      .eq('id', resetToken.user_id);

    if (errUpdate) throw errUpdate;

    const { error: errMarkUsed } = await db
      .from('password_reset_tokens')
      .update({ used: true })
      .eq('token', token);

    if (errMarkUsed) throw errMarkUsed;

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
