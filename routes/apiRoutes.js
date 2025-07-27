const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/authMiddleware');

// Auth Routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// Test Route
router.get('/test', (req, res) => {
  res.json({ message: 'API is working!' });
});

// Protected Routes
router.get('/protected', authenticate, (req, res) => {
  res.json({ message: 'This is protected data', user: req.user });
});

module.exports = router;