const express = require('express');
const router = express.Router();

const {
  createRole,
  assignRole,
  getUserRoles
} = require('../controllers/role.controller');

// Ruta para crear un rol
router.post('/roles', createRole);

// Ruta para asignar rol a usuario
router.post('/roles/assign', assignRole);

// Ruta para ver roles de un usuario
router.get('/roles/user/:user_id', getUserRoles);

module.exports = router;
