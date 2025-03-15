const mysql = require('mysql2/promise');
const config = require('./config');

const pools = {
  auth: mysql.createPool({
    host: config.db.host,
    user: config.db.user,
    password: config.db.password,
    database: config.db.auth_db
  })
};

for (const realm of config.db.realms) {
  pools[realm.db_name] = mysql.createPool({
    host: realm.host,
    user: realm.user,
    password: realm.pass,
    database: realm.db_name
  });
}

module.exports = pools;