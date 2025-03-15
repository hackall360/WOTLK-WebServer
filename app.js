/********************************************************************
 * app.js
 *
 * Complete Express server using SRP6a for registration & login 
 * with a TrinityCore 3.3.5 database. 
 *
 *  - Registration: /register
 *  - SRP Login flow: /login/init (stage1), /login/proof (stage2)
 *  - Display /account with realm/character info
 ********************************************************************/

const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const cheerio = require('cheerio');
require('dotenv').config();

// SRP logic from utils/srp6a.js
const { SRPClient, SRPServer } = require('./utils/srp6a');

// MySQL pool
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-key',
  resave: false,
  saveUninitialized: false
}));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

/********************************************************************
 * Quick item-scraping function
 ********************************************************************/
async function getItemData(itemId) {
  try {
    const url = `https://wotlk.evowow.com/?item=${itemId}`;
    const { data } = await axios.get(url);
    const $ = cheerio.load(data);
    const name = $('h1').text().trim();
    let quality = 'Common';
    if ($('.q4').length > 0) quality = 'Epic';
    else if ($('.q3').length > 0) quality = 'Rare';
    const bgStyle = $('.iconlarge ins').css('background-image') || '';
    const iconMatch = bgStyle.match(/url\((['"]?)(.+?)\1\)/);
    const icon = iconMatch ? iconMatch[2] : '';
    return { name, quality, icon };
  } catch (err) {
    console.error('Failed to scrape item:', itemId, err.message);
    return { name: `Item ${itemId}`, quality: 'Unknown', icon: '' };
  }
}

/********************************************************************
 * Routes
 ********************************************************************/

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Show login page
app.get('/login', (req, res) => {
  res.render('login', { user: req.session.user });
});

// Show register page
app.get('/register', (req, res) => {
  res.render('register', { user: req.session.user });
});

/********************************************************************
 * Registration
 *  - Create new user with SRP salt & verifier.
 *  - Auto-login by setting session user.
 ********************************************************************/
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Invalid username/password');
  }

  try {
    // Check if user already exists
    const [rows] = await pool.execute(
      'SELECT id FROM auth.account WHERE username = ?',
      [username.toUpperCase()]
    );
    if (rows.length > 0) {
      return res.send('Username already exists');
    }

    // Create SRP verifier
    const srpClient = new SRPClient();
    const salt = srpClient.generateSalt(); // 16 bytes
    const verifier = srpClient.computeVerifier(username, password, salt);

    // Insert new account
    await pool.execute(
      'INSERT INTO auth.account (username, salt, verifier) VALUES (?, ?, ?)',
      [username.toUpperCase(), salt, verifier]
    );

    // Auto-login
    req.session.user = username.toUpperCase();
    res.redirect('/account');
  } catch (err) {
    console.error(err);
    res.send('Error creating account');
  }
});

/********************************************************************
 * SRP Login - Stage 1
 *  - The client sends username
 *  - We respond with salt & B
 *  - The client will do its half of SRP, then call /login/proof
 ********************************************************************/
app.post('/login/init', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.json({ success: false, error: 'Missing username' });
  }
  try {
    // Check IP ban etc. if needed
    const [rows] = await pool.execute(
      `SELECT salt, verifier 
         FROM auth.account
        WHERE username = ?`,
      [username.toUpperCase()]
    );
    if (rows.length === 0) {
      return res.json({ success: false, error: 'Unknown account' });
    }
    const saltBuf = Buffer.from(rows[0].salt);
    const verifierBuf = Buffer.from(rows[0].verifier);

    // Create SRPServer
    const srv = new SRPServer();
    srv.setCredentials(username.toUpperCase(), verifierBuf, saltBuf);

    // Store ephemeral server in session
    req.session.srpServer = {
      username: username.toUpperCase(),
      saltHex: saltBuf.toString('hex'),
      Bhex: srv.getPublicKey().toString('hex'),
      bVal: srv.b.toString(), // keep ephemeral 'b' as decimal string
    };

    return res.json({
      success: true,
      salt: saltBuf.toString('hex'),
      B: srv.getPublicKey().toString('hex')
    });
  } catch (err) {
    console.error(err);
    return res.json({ success: false, error: 'Server error' });
  }
});

/********************************************************************
 * SRP Login - Stage 2
 *  - The client sends A & M1
 *  - We re-instantiate an SRPServer, set ephemeral b from session,
 *    then check the proof. If valid -> login success
 ********************************************************************/
app.post('/login/proof', async (req, res) => {
  const { username, A, M1 } = req.body;
  const sdata = req.session.srpServer;
  if (!sdata) {
    return res.json({ success: false, error: 'No SRP session' });
  }
  try {
    // Rebuild SRPServer
    const srv = new SRPServer();
    srv.b = BigInt(sdata.bVal); // ephemeral b from session
    srv.B = BigInt('0x' + sdata.Bhex);
    srv.username = sdata.username;
    srv.salt = Buffer.from(sdata.saltHex, 'hex');
    srv.verifier = Buffer.from(
      (
        await pool.execute(
          'SELECT verifier FROM auth.account WHERE username = ?',
          [username.toUpperCase()]
        )
      )[0][0].verifier
    );
    srv.state = 'ready';

    // Check client proof
    const resp = srv.checkClientProof(A, M1);
    if (!resp.ok) {
      return res.json({ success: false, error: resp.error });
    }
    // If success, set session user
    req.session.user = username.toUpperCase();
    delete req.session.srpServer;
    return res.json({ success: true, M2: resp.M2.toString('hex') });
  } catch (err) {
    console.error(err);
    return res.json({ success: false, error: 'Proof check failed' });
  }
});

/********************************************************************
 * Account page
 *  - Displays user’s realms, characters, items
 ********************************************************************/
app.get('/account', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  try {
    // Get account ID
    const [acctRows] = await pool.execute(
      'SELECT id FROM auth.account WHERE username = ?',
      [req.session.user]
    );
    if (acctRows.length === 0) {
      return res.send('No such user?');
    }
    const accountId = acctRows[0].id;

    // Realmlist
    const [realms] = await pool.execute('SELECT id, name FROM auth.realmlist');
    const realmMap = {};
    for (const r of realms) {
      realmMap[r.id] = { name: r.name, characters: [] };
    }

    // Characters
    const [chars] = await pool.execute(
      'SELECT guid, name, level, race, class FROM characters.characters WHERE account = ?',
      [accountId]
    );

    for (const c of chars) {
      // Items in slots 0..18
      const [invRows] = await pool.execute(
        'SELECT item FROM characters.character_inventory WHERE guid = ? AND bag = 0 AND slot BETWEEN 0 AND 18',
        [c.guid]
      );
      const items = [];
      for (const ir of invRows) {
        const [itRows] = await pool.execute(
          'SELECT entry FROM characters.item_instance WHERE guid = ?',
          [ir.item]
        );
        if (itRows.length > 0) {
          const itemId = itRows[0].entry;
          const itemData = await getItemData(itemId);
          items.push({ id: itemId, ...itemData });
        }
      }
      c.items = items;

      // Hard-code realm=1 or adapt if your DB tracks it
      const realmId = 1;
      if (realmMap[realmId]) {
        realmMap[realmId].characters.push(c);
      }
    }

    res.render('account', {
      user: req.session.user,
      realms: Object.values(realmMap)
    });
  } catch (err) {
    console.error(err);
    return res.send('Error fetching account data');
  }
});

/********************************************************************
 * Logout
 ********************************************************************/
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

/********************************************************************
 * Start server
 ********************************************************************/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});
