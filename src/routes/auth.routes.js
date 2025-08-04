const express = require('express');
const router = express.Router();
const { 
    register, 
    login, 
    refreshAccessToken, 
    logout, 
    forgotPassword, 
    resetPassword 
} = require('../controllers/auth.controller');
const verifyToken = require('../middlewares/auth.middleware');

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refreshAccessToken);
router.post('/logout', verifyToken, logout);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

module.exports = router;