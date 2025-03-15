module.exports = {
  db: {
    host: 'localhost',
    user: 'wowuser',
    password: 'wowpass',
    auth_db: 'auth_db',
    realms: [
      {
        id: 1,
        db_name: 'char_db_1',
        host: 'localhost',
        user: 'wowuser',
        pass: 'wowpass',
        display_name: 'Azeroth' // Friendly name for account page
      }
    ]
  },
  server_core: 'trinitycore'
};