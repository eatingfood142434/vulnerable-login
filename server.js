// server.js
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');

// Create a connection pool for better performance and safety
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'myapp',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const app = express();
app.use(bodyParser.json());

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Input validation: ensure types and length
  if (typeof username !== 'string' || typeof password !== 'string' ||
      username.length > 50 || password.length > 50) {
    return res.status(400).json({ error: 'Invalid username or password format.' });
  }

  // Parameterized query to prevent SQL injection
  const sql = 'SELECT id, password FROM users WHERE username = ? AND password = ?';
  const params = [username, password];

  pool.execute(sql, params, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    if (results.length === 1) {
      // Authentication successful
      return res.status(200).json({ message: 'Login successful.' });
    }

    // Authentication failed
    return res.status(401).json({ error: 'Invalid credentials.' });
  });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});