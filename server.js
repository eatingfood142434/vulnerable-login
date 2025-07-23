// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// Load secrets from environment
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('Missing required environment variables. Please set JWT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD.');
  process.exit(1);
}

// Pre-hash the admin password on startup
const users = [
  {
    username: ADMIN_USERNAME,
    passwordHash: bcrypt.hashSync(ADMIN_PASSWORD, 10)
  }
];

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Input validation
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password must be strings.' });
  }

  // Find user by username
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  // Compare hashed password
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  // Issue JSON Web Token
  const token = jwt.sign(
    { username: user.username },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Set secure HTTP-only cookie
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,         // ensure HTTPS
    sameSite: 'Strict',
    maxAge: 60 * 60 * 1000 // 1 hour
  });

  return res.json({ message: 'Logged in successfully.' });
});

app.post('/logout', (req, res) => {
  // Clear the authentication cookie
  res.clearCookie('auth_token');
  return res.json({ message: 'Logged out successfully.' });
});

// Example protected route
app.get('/profile', (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ username: payload.username });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));