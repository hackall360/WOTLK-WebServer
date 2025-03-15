const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const config = require('./config');
const authRoutes = require('./routes/auth');
const accountRoutes = require('./routes/account');
const pools = require('./db');

const app = express();

// Session store configuration using MySQL
const sessionStoreOptions = {
  host: config.db.host, // 'localhost'
  port: 3306, // Default MySQL port
  user: config.db.user, // 'wowuser'
  password: config.db.password, // 'wowpass'
  database: config.db.auth_db, // 'auth_db'
  clearExpired: true, // Automatically remove expired sessions
  checkExpirationInterval: 15 * 60 * 1000, // Check every 15 minutes
  expiration: 7 * 24 * 60 * 60 * 1000 // 7 days, matching cookie maxAge
};

const sessionStore = new MySQLStore(sessionStoreOptions);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'f050e7faf44297be1c907bec5817ed02387e7bed3b54d6b0b8b364ace665e147', // Replace with your 32-character string
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    secure: false, // Set to true in production with HTTPS
    sameSite: 'lax'
  }
}));

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', async (req, res) => {
  const user = req.session.user || null;
  let usersOnline = 0;
  let realmsStatus = [];

  try {
    if (user) {
      const [onlineAccounts] = await pools.auth.query(
        'SELECT COUNT(*) as count FROM account WHERE online = 1'
      );
      usersOnline = onlineAccounts[0].count;

      for (const realm of config.db.realms) {
        try {
          const [chars] = await pools[realm.db_name].query(
            'SELECT COUNT(*) as count FROM characters WHERE online = 1'
          );
          const isLive = chars[0].count > 0;
          realmsStatus.push({ name: realm.display_name || realm.db_name, isLive });
        } catch (err) {
          realmsStatus.push({ name: realm.display_name || realm.db_name, isLive: false });
          console.error(`Error checking realm ${realm.db_name}:`, err);
        }
      }
    }
    res.render('index', { user, usersOnline, realmsStatus });
  } catch (err) {
    console.error('Error fetching home page data:', err);
    res.render('index', { user, usersOnline: 0, realmsStatus: [] });
  }
});

app.get('/login', (req, res) => res.render('login', { user: req.session.user || null, error: null }));
app.get('/register', (req, res) => res.render('register', { user: req.session.user || null, success: null, error: null }));
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});
app.get('/setup', (req, res) => res.render('setup', { user: req.session.user || null }));

app.use('/', authRoutes);
app.use('/', accountRoutes);

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));