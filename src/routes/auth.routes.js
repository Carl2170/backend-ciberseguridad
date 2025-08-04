const express = require('express');
const router = express.Router();
const { 
    register, 
    loginWithOtp,
    refreshAccessToken, 
    logout, 
    forgotPassword, 
    resetPassword,
    verifyOtpAndLogin
} = require('../controllers/auth.controller');
const verifyToken = require('../middlewares/auth.middleware');

router.post('/register', register);
router.post('/login', loginWithOtp);
router.post('/refresh', refreshAccessToken);
router.post('/logout', verifyToken, logout);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/verify-otp', verifyOtpAndLogin);

module.exports = router;