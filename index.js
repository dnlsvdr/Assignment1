require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const app = express();

const PORT = process.env.PORT || 5000;

// — Connect to MongoDB (cleaned up)
mongoose
  .connect(
    `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`
  )
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// — Define User model
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  user_type: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// — Middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`
    }),
    cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
  })
);

// — Routes —

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Signup form
app.get('/signup', (req, res) => {
  res.render('signup');
});

// Login form
app.get('/login', (req, res) => {
  res.render('login');
});

// Members (protected)
app.get('/members', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('members', { user: req.session.user });
});

// Admin (protected + role check)
app.get('/admin', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.user_type !== 'admin') {
    return res.status(403).render('403');
  }
  // You’d fetch all users here
  res.render('admin', { users: [] });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Logout error');
    res.redirect('/');
  });
});

// Catch‑all 404
app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
