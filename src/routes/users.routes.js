// users.routes.js
const express = require('express');
const verifyToken = require('../middlewares/auth.middleware');
const verifyRole = require('../middlewares/role.middleware');
const router = express.Router();

router.get('/admin/dashboard', verifyToken, verifyRole('admin'), (req, res) => {
  res.json({ msg: 'Bienvenido Admin' });
});

module.exports = router;