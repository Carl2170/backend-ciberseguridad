const jwt = require('jsonwebtoken');

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '45m' });
};

const generateRefreshToken = () => {
  return require('crypto').randomBytes(64).toString('hex');
};

module.exports = { generateAccessToken, generateRefreshToken };
