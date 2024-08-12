const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(bodyParser.json());

const allowedOrigins = [
    'http://localhost:5173/',
    'https://shiny-top.vercel.app/',
    // Add more allowed origins here
];
  
const corsOptions = {
    origin: (origin, callback) => {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};
  
app.use(cors(corsOptions)); 

const db = new sqlite3.Database('Quema.db');
const JWT_SECRET = process.env.JWT_SECRET; 

// Middleware to check JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    console.log('Received Token:', token); // Log the token

    if (token == null) {
        console.log('No token provided');
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// User registration
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Server error');
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
            if (err) {
                console.error(err.message); // Log the error
                return res.status(500).send('User already exists');
            }
            res.status(201).send({ id: this.lastID });
        });
    });
});

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            console.error(err.message); // Log the error
            return res.status(500).send('Server error');
        }
        if (!user) return res.status(401).send('User not found');
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                console.error(err.message); // Log the error
                return res.status(500).send('Server error');
            }
            if (!match) return res.status(401).send('Invalid credentials');
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
            res.json({ token });
        });
    });
});

// Create a post
app.post('/posts', authenticateJWT, (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id;
    db.run("INSERT INTO posts (title, content, userId) VALUES (?, ?, ?)", [title, content, userId], function (err) {
        if (err) return res.status(500).send('Error creating post');
        res.status(201).send({ id: this.lastID });
    });
});

// Get all posts
app.get('/posts', (req, res) => {
    db.all("SELECT * FROM posts", [], (err, rows) => {
        if (err) return res.status(500).send('Error fetching posts');
        res.json(rows);
    });
});

app.put('/posts/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;
    const userId = req.user.id;

    db.run(
        "UPDATE posts SET title = ?, content = ? WHERE id = ? AND userId = ?",
        [title, content, id, userId],
        function (err) {
            if (err) {
                console.error('Update error:', err.message);
                return res.status(500).send('Error updating post');
            }
            if (this.changes === 0) {
                return res.status(404).send('Post not found or you do not have permission to update this post');
            }
            res.status(200).send('Post updated successfully');
        }
    );
});

app.delete('/posts/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    db.run(
        "DELETE FROM posts WHERE id = ? AND userId = ?",
        [id, userId],
        function (err) {
            if (err) {
                console.error('Delete error:', err.message);
                return res.status(500).send('Error deleting post');
            }
            if (this.changes === 0) {
                return res.status(404).send('Post not found or you do not have permission to delete this post');
            }
            res.status(200).send('Post deleted successfully');
        }
    );
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});