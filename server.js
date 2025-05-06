require('dotenv').config({ path: './mongo.env' })                     

const express        = require('express')
const bcrypt         = require('bcrypt')
const session        = require('express-session')
const MongoDBSession = require('connect-mongodb-session')(session)
const mongoose       = require('mongoose')
const path           = require('path')

const app = express()
const UserModel = require("./models/user")

const mongoURI = process.env.MONGODB_CONNECTION_STRING

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB Connected"))
.catch(err => console.error(err))

app.use(express.static(path.join(__dirname, "public")))

const store = new MongoDBSession({
  uri: mongoURI,
  collection: "mySessions",
  expires: 1000 * 60 * 60                
})

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: true }))

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: {
    maxAge: 1000 * 60 * 60              
  }
}))

const isAuth = (req, res, next) => {
  if (req.session.isAuth) {
    return next()
  }
  res.redirect("/login")
}

app.get("/", (req, res) => {                 
  res.render("landing")
})

app.get("/members", isAuth, (req, res) => {   
  const images = [
    "/images/meow1.jpeg",
    "/images/meow2.jpeg",
    "/images/meow3.jpeg"
  ]
  const imageUrl = images[Math.floor(Math.random() * images.length)]
  res.render("members", {
    user: req.session.user,
    imageUrl                         
  })
})

app.get("/signup", (req, res) => {
  res.render("signup", { error: null })
})

app.post("/signup", async (req, res) => {
  const Joi = require("joi")
  const schema = Joi.object({
    name:     Joi.string().max(30).required(),
    email:    Joi.string().email().required(),
    password: Joi.string().min(6).required()
  })
  const { error, value } = schema.validate(req.body)
  if (error) {
    return res.render("signup", { error: error.details[0].message })
  }

  const { name, email, password } = value
  let user = await UserModel.findOne({ email })
  if (user) {
    return res.render("signup", { error: "Email already in use." })
  }

  const hashedPsw = await bcrypt.hash(password, 12)
  user = new UserModel({ name, email, password: hashedPsw })
  await user.save()

  req.session.user   = { id: user._id, name: user.name }
  req.session.isAuth = true
  res.redirect("/members")            
})

app.get("/login", (req, res) => {
  res.render("login", { error: null })
})

app.post("/login", async (req, res) => {
  const Joi = require("joi")
  const schema = Joi.object({
    email:    Joi.string().email().required(),
    password: Joi.string().required()
  })
  const { error, value } = schema.validate(req.body)
  if (error) {
    return res.render("login", { error: error.details[0].message })
  }

  const { email, password } = value
  const user = await UserModel.findOne({ email })
  if (!user) {
    return res.render("login", { error: "No user found with that email." })
  }

  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
    return res.render("login", { error: "Incorrect password." })
  }

  req.session.user   = { id: user._id, name: user.name }
  req.session.isAuth = true
  res.redirect("/members")                  
})

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) throw err
    res.redirect("/")                    
  })
})

app.use((req, res) => {
  res.status(404).render("404")
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
