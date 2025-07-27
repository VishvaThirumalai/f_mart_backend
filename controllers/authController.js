// server/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Helper functions
const readData = (file) => {
  try {
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error reading ${file}:`, err);
    return [];
  }
};

const writeData = (file, data) => {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error(`Error writing to ${file}:`, err);
    return false;
  }
};

// JWT configuration
const jwtConfig = {
  expiresIn: '7d',
  issuer: 'freshmart-api'
};

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const USERS_FILE = path.join(__dirname, '../data/users.json');

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'All fields are required'
      });
    }

    if (name.trim().length < 2) {
      return res.status(400).json({ 
        success: false,
        message: 'Name must be at least 2 characters'
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid email format'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    const users = readData(USERS_FILE);
    
    // Check if user exists
    if (users.some(user => user.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create new user
    const newUser = { 
      id: Date.now(), 
      name: name.trim(), 
      email: email.toLowerCase(), 
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    if (!writeData(USERS_FILE, users)) {
      return res.status(500).json({ 
        success: false,
        message: 'Failed to save user data'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email }, 
      process.env.JWT_SECRET, 
      jwtConfig
    );
    
    // Return response without password
    const userResponse = {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email
    };
    
    return res.status(201).json({ 
      success: true,
      message: 'Registration successful',
      user: userResponse, 
      token
    });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ 
      success: false,
      message: 'Server error during registration'
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const USERS_FILE = path.join(__dirname, '../data/users.json');

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and password required'
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid email format'
      });
    }

    const users = readData(USERS_FILE);
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email }, 
      process.env.JWT_SECRET, 
      jwtConfig
    );
    
    // Return response without password
    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email
    };
    
    return res.json({ 
      success: true,
      message: 'Login successful',
      user: userResponse, 
      token
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ 
      success: false,
      message: 'Server error during login'
    });
  }
};