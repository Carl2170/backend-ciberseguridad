const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail', // O usa otro: 'hotmail', 'mailgun', 'outlook', etc.
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_KEY,
  },
});

const sendPasswordResetEmail = async (to, token) => {
    const resetLink = `${process.env.FRONTEND_URL}/api/auth/reset-password?token=${token}`;
    console.log(process.env.EMAIL_USER, process.env.EMAIL_KEY, resetLink);
    
  await transporter.sendMail({
    from: `"SecureZone App" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Recuperación de contraseña',
    html: `
      <h2>Recuperación de contraseña</h2>
      <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
      <a href="${resetLink}" target="_blank">${resetLink}</a>
      <p>Este enlace expirará en 15 minutos.</p>
    `,
  });
};

const sendOtpEmail = async (to, otpCode) => {
  try {
    await transporter.sendMail({
      from: `"SecureZone App" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Tu código de verificación',
      html: `
        <h2>Verificación de inicio de sesión</h2>
        <p>Tu código de verificación de un solo uso (OTP) es:</p>
        <p style="font-size: 24px; font-weight: bold; color: #007bff;">${otpCode}</p>
        <p>Este código es válido por 5 minutos.</p>
      `,
    });
    console.log(`OTP enviado a ${to} exitosamente.`);
  } catch (error) {
    console.error('Error al enviar el correo OTP:', error);
  }
};

module.exports = { sendPasswordResetEmail, sendOtpEmail };
