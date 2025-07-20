// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// Create a connection pool for MySQL with environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Input validation: ensure both username and password are provided
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types' });
  }

  try {
    // Use parameterized query to prevent SQL injection
    const sql = 'SELECT id, username, password_hash FROM users WHERE username = ?';
    const [rows] = await pool.execute(sql, [username]);

    if (rows.length === 0) {
      // Do not reveal whether username or password is invalid
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];

    // Compare provided password with stored hash
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // TODO: Issue JWT or session cookie here
    res.json({ message: 'Login successful', userId: user.id });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});