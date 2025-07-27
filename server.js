require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// ========== Middleware Setup ==========
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api', limiter);

// ========== Data Management ==========
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CARTS_FILE = path.join(DATA_DIR, 'carts.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Initialize data directory
const initializeData = () => {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  
  [USERS_FILE, CARTS_FILE, ORDERS_FILE].forEach(file => {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify([], null, 2));
    }
  });
};

// Data helpers
const readData = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
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
    console.error(`Error writing ${file}:`, err);
    return false;
  }
};

// ========== Authentication ==========
const jwtConfig = {
  expiresIn: '7d',
  issuer: 'freshmart-api'
};

const authenticate = (req, res, next) => {
  if (req.method === 'OPTIONS') return next();

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) throw new Error('No token provided');
    
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({
      success: false,
      message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
    });
  }
};

// ========== Routes ==========

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
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
    if (users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: Date.now(),
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    if (!writeData(USERS_FILE, users)) {
      throw new Error('Failed to save user data');
    }

    // Initialize cart
    const carts = readData(CARTS_FILE);
    carts.push({ userId: newUser.id, items: [] });
    writeData(CARTS_FILE, carts);

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      process.env.JWT_SECRET,
      jwtConfig
    );

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email
      },
      token
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password required'
      });
    }

    const users = readData(USERS_FILE);
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      jwtConfig
    );

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      token
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// ========== CART ROUTES ==========

// Get user cart
app.get('/api/cart', authenticate, (req, res) => {
  try {
    const carts = readData(CARTS_FILE);
    const userCart = carts.find(c => c.userId === req.user.id) || { userId: req.user.id, items: [] };
    
    res.json({ 
      success: true, 
      items: userCart.items || [],
      totalItems: userCart.items?.reduce((sum, item) => sum + item.quantity, 0) || 0,
      totalPrice: userCart.items?.reduce((sum, item) => sum + (item.price * item.quantity), 0) || 0
    });
  } catch (err) {
    console.error('Cart fetch error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch cart'
    });
  }
});

// Add item to cart
app.post('/api/cart', authenticate, (req, res) => {
  try {
    const { productId, name, price, image, quantity = 1 } = req.body;
    
    // Validation
    if (!productId || !name || !price) {
      return res.status(400).json({
        success: false,
        message: 'Product ID, name, and price are required'
      });
    }

    if (quantity < 1) {
      return res.status(400).json({
        success: false,
        message: 'Quantity must be at least 1'
      });
    }

    const carts = readData(CARTS_FILE);
    let userCart = carts.find(c => c.userId === req.user.id);
    
    if (!userCart) {
      userCart = { userId: req.user.id, items: [] };
      carts.push(userCart);
    }

    const existingItemIndex = userCart.items.findIndex(item => item.productId == productId);
    
    if (existingItemIndex !== -1) {
      // Update existing item quantity
      userCart.items[existingItemIndex].quantity += quantity;
    } else {
      // Add new item
      userCart.items.push({ 
        productId: productId.toString(), 
        name, 
        price: parseFloat(price), 
        image, 
        quantity: parseInt(quantity),
        addedAt: new Date().toISOString()
      });
    }

    if (!writeData(CARTS_FILE, carts)) {
      throw new Error('Failed to update cart');
    }

    const totalItems = userCart.items.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = userCart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    res.json({ 
      success: true, 
      message: 'Item added to cart successfully',
      items: userCart.items,
      totalItems,
      totalPrice
    });
  } catch (err) {
    console.error('Cart add error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to add item to cart'
    });
  }
});

// Update item quantity in cart
app.put('/api/cart/:productId', authenticate, (req, res) => {
  try {
    const { productId } = req.params;
    const { quantity } = req.body;
    
    if (!quantity || quantity < 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid quantity is required'
      });
    }

    const carts = readData(CARTS_FILE);
    const userCart = carts.find(c => c.userId === req.user.id);
    
    if (!userCart) {
      return res.status(404).json({
        success: false,
        message: 'Cart not found'
      });
    }

    const itemIndex = userCart.items.findIndex(item => item.productId == productId);
    
    if (itemIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Item not found in cart'
      });
    }

    if (quantity === 0) {
      // Remove item if quantity is 0
      userCart.items.splice(itemIndex, 1);
    } else {
      // Update quantity
      userCart.items[itemIndex].quantity = parseInt(quantity);
      userCart.items[itemIndex].updatedAt = new Date().toISOString();
    }
    
    if (!writeData(CARTS_FILE, carts)) {
      throw new Error('Failed to update cart');
    }

    const totalItems = userCart.items.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = userCart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    res.json({ 
      success: true, 
      message: quantity === 0 ? 'Item removed from cart' : 'Cart updated successfully',
      items: userCart.items,
      totalItems,
      totalPrice
    });
  } catch (err) {
    console.error('Cart update error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update cart'
    });
  }
});

// Remove specific item from cart
app.delete('/api/cart/:productId', authenticate, (req, res) => {
  try {
    const { productId } = req.params;
    const carts = readData(CARTS_FILE);
    
    const userCart = carts.find(c => c.userId === req.user.id);
    if (!userCart) {
      return res.status(404).json({
        success: false,
        message: 'Cart not found'
      });
    }

    const initialLength = userCart.items.length;
    userCart.items = userCart.items.filter(item => item.productId != productId);
    
    if (userCart.items.length === initialLength) {
      return res.status(404).json({
        success: false,
        message: 'Item not found in cart'
      });
    }
    
    if (!writeData(CARTS_FILE, carts)) {
      throw new Error('Failed to update cart');
    }

    const totalItems = userCart.items.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = userCart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    res.json({ 
      success: true, 
      message: 'Item removed from cart successfully',
      items: userCart.items,
      totalItems,
      totalPrice
    });
  } catch (err) {
    console.error('Cart remove error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to remove item from cart'
    });
  }
});

// Clear entire cart
app.delete('/api/cart', authenticate, (req, res) => {
  try {
    const carts = readData(CARTS_FILE);
    const userCart = carts.find(c => c.userId === req.user.id);
    
    if (!userCart) {
      return res.status(404).json({
        success: false,
        message: 'Cart not found'
      });
    }

    userCart.items = [];
    userCart.clearedAt = new Date().toISOString();
    
    if (!writeData(CARTS_FILE, carts)) {
      throw new Error('Failed to clear cart');
    }

    res.json({ 
      success: true, 
      message: 'Cart cleared successfully',
      items: [],
      totalItems: 0,
      totalPrice: 0
    });
  } catch (err) {
    console.error('Cart clear error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to clear cart'
    });
  }
});

// ========== ORDER ROUTES ==========

// Get user orders
app.get('/api/orders', authenticate, (req, res) => {
  try {
    const orders = readData(ORDERS_FILE);
    const userOrders = orders.filter(order => order.userId === req.user.id);
    
    // Sort by order date (newest first)
    userOrders.sort((a, b) => new Date(b.orderDate) - new Date(a.orderDate));
    
    res.json({
      success: true,
      orders: userOrders,
      total: userOrders.length
    });
  } catch (err) {
    console.error('Orders fetch error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch orders'
    });
  }
});

// Create new order
app.post('/api/orders', authenticate, (req, res) => {
  try {
    const { items, deliveryAddress, paymentMethod, notes } = req.body;
    
    if (!items || items.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Order items are required'
      });
    }

    if (!deliveryAddress || !paymentMethod) {
      return res.status(400).json({
        success: false,
        message: 'Delivery address and payment method are required'
      });
    }

    const totalAmount = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const orderId = `FM${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
    
    const newOrder = {
      id: orderId,
      userId: req.user.id,
      items: items.map(item => ({
        productId: item.productId,
        name: item.name,
        price: parseFloat(item.price),
        quantity: parseInt(item.quantity),
        image: item.image
      })),
      totalAmount: parseFloat(totalAmount.toFixed(2)),
      deliveryAddress,
      paymentMethod,
      notes: notes || '',
      status: 'confirmed',
      orderDate: new Date().toISOString(),
      estimatedDelivery: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours from now
      createdAt: new Date().toISOString()
    };

    const orders = readData(ORDERS_FILE);
    orders.push(newOrder);
    
    if (!writeData(ORDERS_FILE, orders)) {
      throw new Error('Failed to save order');
    }

    // Clear user's cart after successful order
    const carts = readData(CARTS_FILE);
    const userCart = carts.find(c => c.userId === req.user.id);
    if (userCart) {
      userCart.items = [];
      userCart.clearedAt = new Date().toISOString();
      writeData(CARTS_FILE, carts);
    }

    res.status(201).json({
      success: true,
      message: 'Order placed successfully',
      order: newOrder
    });
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create order'
    });
  }
});

// Cancel order
app.put('/api/orders/:orderId/cancel', authenticate, (req, res) => {
  try {
    const { orderId } = req.params;
    const { reason } = req.body;
    
    const orders = readData(ORDERS_FILE);
    const orderIndex = orders.findIndex(order => 
      order.id === orderId && order.userId === req.user.id
    );
    
    if (orderIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    const order = orders[orderIndex];
    
    // Check if order can be cancelled
    if (['delivered', 'cancelled'].includes(order.status.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: `Cannot cancel order with status: ${order.status}`
      });
    }

    // Update order status
    orders[orderIndex] = {
      ...order,
      status: 'cancelled',
      cancelledAt: new Date().toISOString(),
      cancellationReason: reason || 'Cancelled by customer',
      updatedAt: new Date().toISOString()
    };
    
    if (!writeData(ORDERS_FILE, orders)) {
      throw new Error('Failed to update order');
    }

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      order: orders[orderIndex]
    });
  } catch (err) {
    console.error('Order cancellation error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel order'
    });
  }
});

// Get specific order details
app.get('/api/orders/:orderId', authenticate, (req, res) => {
  try {
    const { orderId } = req.params;
    const orders = readData(ORDERS_FILE);
    
    const order = orders.find(order => 
      order.id === orderId && order.userId === req.user.id
    );
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.json({
      success: true,
      order
    });
  } catch (err) {
    console.error('Order fetch error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch order details'
    });
  }
});

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is healthy',
    timestamp: new Date().toISOString()
  });
});
app.get("/", (req, res) => {
  res.send("Welcome to FreshMart API! Use /api for endpoints.");
});

// Initialize and start server
initializeData();
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
  console.log(`💚 Health Check: http://localhost:${PORT}/api/health`);
});