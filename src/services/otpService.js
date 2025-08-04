const db = require('../config/db.config'); // Importamos la conexión a Supabase
const { hashPassword, verifyPassword } = require('../utils/hash'); // Reusamos las funciones de hash

/**
 * Genera un código OTP de 6 dígitos.
 * @returns {string} El código OTP.
 */
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Guarda un OTP para un usuario, sobrescribiendo cualquier OTP anterior.
 * @param {string} userId - El ID del usuario.
 * @returns {string} El código OTP generado.
 */
const saveOtp = async (userId) => {
  const otpCode = generateOtp();
  const expiresAt = new Date(Date.now() + 5 * 60000); // Expira en 5 minutos
  const hashedOtp = await hashPassword(otpCode); // Usamos bcrypt para hashear el OTP

  try {
    // Upsert para actualizar o insertar un nuevo OTP para el usuario
    const { error } = await db.from('otps')
      .upsert({ user_id: userId, otp_code: hashedOtp, expires_at: expiresAt }, { onConflict: 'user_id' });

    if (error) throw error;
    return otpCode;
  } catch (err) {
    console.error('Error al guardar el OTP:', err);
    return null;
  }
};

/**
 * Verifica si el OTP proporcionado es válido y no ha expirado.
 * @param {string} userId - El ID del usuario.
 * @param {string} otpCode - El código OTP proporcionado por el usuario.
 * @returns {boolean} - Verdadero si el OTP es válido, falso en caso contrario.
 */
const verifyOtp = async (userId, otpCode) => {
  try {
    const { data, error } = await db.from('otps')
      .select('otp_code, expires_at')
      .eq('user_id', userId)
      .single();

    if (error) {
      console.error('Error al buscar el OTP:', error);
      return false;
    }

    if (!data) {
      return false; // No se encontró un OTP para el usuario
    }

    const { otp_code: hashedOtp, expires_at } = data;
    const isExpired = new Date(expires_at) < new Date();
    const isValid = await verifyPassword(otpCode, hashedOtp);

    if (isValid && !isExpired) {
      // El OTP es válido, lo eliminamos de la base de datos para que no pueda ser reutilizado
      await db.from('otps').delete().eq('user_id', userId);
      return true;
    }

    return false;
  } catch (err) {
    console.error('Error al verificar el OTP:', err);
    return false;
  }
};

module.exports = {
  saveOtp,
  verifyOtp
};
