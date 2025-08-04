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
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
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

module.exports = { sendPasswordResetEmail };
