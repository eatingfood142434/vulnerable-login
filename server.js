require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const SALT_ROUNDS = 10;
app.use(express.json());
app.use(cookieParser());

// In-memory user store – replace with real database in production
const users = [];

/**
 * POST /register
 * Registers a new user with hashed password
 */
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    // Prevent duplicate users
    if (users.find(u => u.username === username)) {
      return res.status(409).json({ error: 'User already exists.' });
    }
    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /login
 * Authenticates user and issues a signed JWT in a secure cookie
 */
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    // Compare plaintext password to hashed password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    // Generate JWT
    const token = jwt.sign(
      { username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
    // Set token in HttpOnly, Secure cookie
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.json({ message: 'Login successful.' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * GET /protected
 * Example of a protected route that requires a valid JWT
 */
app.get('/protected', (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: 'Authentication token missing.' });
    }
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ message: `Hello ${payload.username}, you have access.` });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));