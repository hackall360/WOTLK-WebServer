const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const pools = require('../db');

router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  console.log('Received data:', { username, password, email });

  try {
    const [existing] = await pools.auth.query(
      'SELECT id FROM account WHERE username = ?',
      [username.toUpperCase()]
    );
    if (existing.length > 0) {
      return res.render('register', { user: null, success: null, error: 'Username already exists' });
    }

    const sha1Hash = crypto.createHash('sha1')
      .update(`${username.toUpperCase()}:${password.toUpperCase()}`)
      .digest('hex')
      .toUpperCase();

    await pools.auth.query(
      'INSERT INTO account (username, sha_pass_hash, email) VALUES (?, ?, ?)',
      [username.toUpperCase(), sha1Hash, email]
    );

    req.session.user = username.toUpperCase();
    res.redirect('/account?registered=true');
  } catch (err) {
    console.error('Database error:', err);
    res.render('register', { user: null, success: null, error: err.message });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const sha1Hash = crypto.createHash('sha1')
      .update(`${username.toUpperCase()}:${password.toUpperCase()}`)
      .digest('hex')
      .toUpperCase();

    const [rows] = await pools.auth.query(
      'SELECT id, username FROM account WHERE username = ? AND sha_pass_hash = ?',
      [username.toUpperCase(), sha1Hash]
    );

    if (rows.length === 0) {
      return res.render('login', { user: null, error: 'Invalid credentials' });
    }

    req.session.user = rows[0].username;
    res.redirect('/account');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { user: null, error: err.message });
  }
});

module.exports = router;