require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const app = express();
const PORT = process.env.PORT || 8000;

mongoose
  .connect(
    `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`
  )
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  user_type: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

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
    cookie: { maxAge: 1000 * 60 * 60 }
  })
);

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user, active: 'home' });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null, active: 'signup' });
});

app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.render('signup', { error: error.details[0].message, active: 'signup' });
  const hash = await bcrypt.hash(value.password, 10);
  await User.create({ name: value.name, email: value.email, password: hash });
  req.session.user = { name: value.name, email: value.email, user_type: 'user' };
  res.redirect('/members');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, active: 'login' });
});

app.post('/login', async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.render('login', { error: error.details[0].message, active: 'login' });
  const user = await User.findOne({ email: value.email });
  if (!user || !(await bcrypt.compare(value.password, user.password))) {
    return res.render('login', { error: 'Invalid email or password', active: 'login' });
  }
  req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
  res.redirect('/members');
});

app.get('/members', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('members', { user: req.session.user, active: 'members' });
});

app.get('/admin', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.user_type !== 'admin') {
    return res
      .status(403)
      .send(
        `<div class="container text-center my-5"><h1>403 — Not Authorized</h1><p>You don’t have permission to view this page.</p><a href="/" class="btn btn-primary">Return Home</a></div>`
      );
  }
  const users = await User.find().lean();
  res.render('admin', { users, active: 'admin' });
});

app.post('/admin/toggle/:id', async (req, res) => {
  const u = await User.findById(req.params.id);
  u.user_type = u.user_type === 'admin' ? 'user' : 'admin';
  await u.save();
  res.redirect('/admin');
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => (err ? res.status(500).send('Logout error') : res.redirect('/')));
});

app.use((req, res) => {
  res.status(404).render('404', { active: null });
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
