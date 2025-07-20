require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const app = express();

// Rate limiter to prevent brute-force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 login requests per windowMs
  message: { error: 'Too many login attempts, please try again later.' }
});

app.use(bodyParser.json());

// In-memory user store for demo; replace with database calls
const users = [
  // Example user: password hashed with bcrypt
  { id: 1, username: 'alice', passwordHash: '$2b$12$abcdefghijklmnopqrstuv' }
];

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input types.' });
    }
    const user = users.find(u => u.username === username);
    if (!user) {
      // Do not reveal whether username or password was invalid
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { sub: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Protected route example
app.get('/profile', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // In real app, retrieve user data from database
    res.json({ id: payload.sub, username: payload.username });
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));