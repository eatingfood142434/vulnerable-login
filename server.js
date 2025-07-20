// server.js
require('dotenv').config();                              // Load environment variables
const express = require('express');
const mysql   = require('mysql');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Create a connection pool to improve performance and manage connections safely
const pool = mysql.createPool({
  connectionLimit : 10,
  host            : process.env.DB_HOST,
  user            : process.env.DB_USER,
  password        : process.env.DB_PASSWORD,
  database        : process.env.DB_NAME
});

// Login endpoint with parameterized query to prevent SQL injection
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Basic input validation
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ error: 'Invalid username or password format.' });
  }

  const sql = 'SELECT id, username, role FROM users WHERE username = ? AND password = ?';
  const params = [username, password];

  pool.query(sql, params, (err, results) => {
    if (err) {
      console.error('Database error on login:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    if (results.length === 0) {
      // Credentials did not match any record
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // At this point, authentication succeeded
    const user = results[0];
    // TODO: Issue a session token or JWT here
    return res.json({ success: true, user });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});