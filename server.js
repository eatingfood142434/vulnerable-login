// server.js (Secure Version)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// In-memory user store (replace with real DB in production)
const users = [];

// Utility: generate JWT for authenticated users
function generateToken(user) {
  return jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Middleware: verify JWT and attach user to request
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });
  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ message: 'Token invalid or expired' });
    req.user = payload;  // { username, role }
    next();
  });
}

// Middleware: enforce role-based authorization
function authorizeRole(requiredRole) {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).json({ message: 'Insufficient privileges' });
    }
    next();
  };
}

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  // Check if user already exists
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ message: 'User already exists' });
  }
  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, role: role || 'user' });
  res.status(201).json({ message: 'User registered successfully' });
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  // Compare hashed password
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  // Generate and return JWT
  const token = generateToken(user);
  res.json({ token });
});

// Example of a protected route accessible to any authenticated user
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Hello, ${req.user.username}`, role: req.user.role });
});

// Example of an admin-only endpoint
app.delete('/admin/user/:username', authenticateToken, authorizeRole('admin'), (req, res) => {
  const target = users.findIndex(u => u.username === req.params.username);
  if (target < 0) return res.status(404).json({ message: 'User not found' });
  users.splice(target, 1);
  res.json({ message: 'User deleted' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});