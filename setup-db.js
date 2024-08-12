const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('Quema.db');

db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, userId INTEGER, FOREIGN KEY(userId) REFERENCES users(id))");
});

db.close();