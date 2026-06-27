const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'your_secret_key_change_this_in_production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database Setup
const db = new sqlite3.Database('./ecommerce.db');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Products table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image TEXT,
    stock INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total_amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Order items table
  db.run(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);

  // Insert sample products if not exists
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row.count === 0) {
      const sampleProducts = [
        { name: 'Laptop', description: 'High-performance laptop for work and gaming', price: 999.99, image: '🖥️', stock: 10 },
        { name: 'Smartphone', description: 'Latest smartphone with advanced features', price: 799.99, image: '📱', stock: 20 },
        { name: 'Headphones', description: 'Noise-cancelling wireless headphones', price: 199.99, image: '🎧', stock: 30 },
        { name: 'Tablet', description: 'Portable tablet for entertainment and work', price: 499.99, image: '📱', stock: 15 },
        { name: 'Camera', description: 'Professional DSLR camera', price: 1299.99, image: '📷', stock: 8 },
        { name: 'Smartwatch', description: 'Feature-rich smartwatch with health tracking', price: 349.99, image: '⌚', stock: 25 }
      ];

      sampleProducts.forEach(product => {
        db.run(
          "INSERT INTO products (name, description, price, image, stock) VALUES (?, ?, ?, ?, ?)",
          [product.name, product.description, product.price, product.image, product.stock]
        );
      });
    }
  });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hashedPassword],
    function(err) {
      if (err) {
        return res.status(400).json({ message: 'User already exists' });
      }

      const token = jwt.sign({ id: this.lastID, username, email }, JWT_SECRET, { expiresIn: '24h' });
      res.status(201).json({ 
        message: 'User registered successfully',
        token,
        user: { id: this.lastID, username, email }
      });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ 
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  });
});

// ===== PRODUCT ROUTES =====

// Get all products
app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM products", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(rows);
  });
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  db.get("SELECT * FROM products WHERE id = ?", [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!row) return res.status(404).json({ message: 'Product not found' });
    res.json(row);
  });
});

// ===== CART ROUTES =====

// Cart is stored in localStorage on frontend, but we can verify products exist
app.post('/api/cart/validate', (req, res) => {
  const { items } = req.body;
  
  if (!items || items.length === 0) {
    return res.status(400).json({ message: 'Cart is empty' });
  }

  const ids = items.map(item => item.id).join(',');
  db.all(`SELECT id, price, stock FROM products WHERE id IN (${ids})`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(rows);
  });
});

// ===== ORDER ROUTES =====

// Create order
app.post('/api/orders', authenticateToken, (req, res) => {
  const { items, totalAmount } = req.body;
  const userId = req.user.id;

  if (!items || items.length === 0 || !totalAmount) {
    return res.status(400).json({ message: 'Invalid order data' });
  }

  db.run(
    "INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, ?)",
    [userId, totalAmount, 'processing'],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error creating order' });

      const orderId = this.lastID;
      let completed = 0;

      // Add order items
      items.forEach(item => {
        db.run(
          "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
          [orderId, item.id, item.quantity, item.price],
          (err) => {
            completed++;
            if (completed === items.length) {
              // Update product stock
              items.forEach(item => {
                db.run(
                  "UPDATE products SET stock = stock - ? WHERE id = ?",
                  [item.quantity, item.id]
                );
              });

              res.status(201).json({ 
                message: 'Order created successfully',
                orderId,
                status: 'processing'
              });
            }
          }
        );
      });
    }
  );
});

// Get user orders
app.get('/api/orders', authenticateToken, (req, res) => {
  db.all(
    `SELECT o.*, GROUP_CONCAT(oi.product_id || ':' || oi.quantity) as items
     FROM orders o
     LEFT JOIN order_items oi ON o.id = oi.order_id
     WHERE o.user_id = ?
     GROUP BY o.id
     ORDER BY o.created_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json(rows);
    }
  );
});

// Get order details
app.get('/api/orders/:id', authenticateToken, (req, res) => {
  db.get(
    "SELECT * FROM orders WHERE id = ? AND user_id = ?",
    [req.params.id, req.user.id],
    (err, order) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (!order) return res.status(404).json({ message: 'Order not found' });

      db.all(
        "SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
        [req.params.id],
        (err, items) => {
          if (err) return res.status(500).json({ message: 'Database error' });
          res.json({ ...order, items });
        }
      );
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Database: ecommerce.db');
});
