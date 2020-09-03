const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const passport = require('passport')
    , LocalStrategy = require('passport-local').Strategy;
const bcrypt = require("bcrypt");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
require('dotenv').config();
const findOrCreate = require('mongoose-find-or-create');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(express.static(__dirname + '/public'));
app.use(session({
    secret: "This is our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
mongoose.connect("mongodb+srv://amged:" + process.env.DB_PASS + "@cluster0.soiz5.mongodb.net/userslist", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});
userSchema = new mongoose.Schema({
    username: {
        type: String
    },
    firstname: {
        type: String
    },
    lastname: {
        type: String
    },
    password: {
        type: String,
        minlength: 6,
    },
    email: {
        type: String
    },
    phoneNumber: {
        type: Number
    },
    birthday: {
        type: String
    },
    googleId: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
},
    function (email, password, done) {
        User.findOne({ email: email }, async function (err, user) {
            if (err) { return done(err); }
            if (!user) {
                return done(null, false, { message: 'Incorrect credentials.' });
            }
            const validatePassword = await bcrypt.compare(password, user.password);
            if (!validatePassword) {
                return done(null, false, { message: 'Incorrect credentials.' });
            }
            return done(null, user);
        });
    }
));
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.G_CLIENT_ID,
    clientSecret: process.env.G_CLIENT_SEC,
    callbackURL: "/auth/google/list",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id,
            username: profile.displayName,
            firstname: profile._json.given_name,
            lastname: profile._json.family_name,
            email: profile._json.email,
            phoneNumber: profile.phone_number,
            birthday: profile.birthday
        }, function (err, user) {
            return cb(err, user);
        });

    }
));
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GET to /
// PUBLIC
// show all users 
app.get("/", async (req, res) => {
    if (req.isAuthenticated()) {
        const users = await User.find({}).select("-password");
        res.render("userslist", {
            Users: users
        });
    } else {
        res.redirect("/login");
    }

});
///////////////////////REGISTER NEW USER///////////////////////////////
// GET to /users
// PUBLIC
// REGISTER A NEW USER 
app.get("/register", async (req, res) => {
    res.render("signup");
});
///////////////////////REGISTER NEW USER///////////////////////////////
// POST to /users
// PUBLIC
// REGISTER A NEW USER 
app.post("/users", async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
        username: req.body.uname,
        firstname: req.body.fname,
        lastname: req.body.lname,
        password: hashedPassword,
        email: req.body.email,
        phoneNumber: req.body.phone,
        birthday: req.body.birthday
    });
    const emailCheck = await User.findOne({ email: req.body.email });
    if (emailCheck) {
        res.send("Email is already registered to our database");
    }
    try {
        await user.save();
        passport.authenticate("local")(req, res, function () {
            res.redirect("/");
        });
    } catch (err) {
        console.log(err);
    }
});
///////////////////////LOGIN USER///////////////////////////////
// POST to /login
// PUBLIC
// REGISTER A NEW USER 
app.post("/login", (req, res) => {
    const user = new User({
        email: req.body.email,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            return console.log(err);
        }
        req.login(user, (err) => {
            if (err) {
                return res.send(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/");
                });
            }
        });
    });
});
///////////////////////LOGOUT USER///////////////////////////////
// GET to /logout
// PRIVATE
// LOGOUT USER 
app.get("/logout", (req, res) => {
    console.log(req.user);
    req.logout();
    res.redirect("/login");
});

///////////////////////LOGIN PAGE///////////////////////////////
// GET to /login
// PUBLIC
// LOGIN PAGE 
app.get("/login", (req, res) => {
    res.render("login")
});
///////////////////////GOOGLE AUTH///////////////////////////////
app.get('/auth/google',
    passport.authenticate('google', {
        scope: [
            'https://www.googleapis.com/auth/user.phonenumbers.read',
            'https://www.googleapis.com/auth/userinfo.email',
            "https://www.googleapis.com/auth/user.birthday.read",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    }));
app.get('/auth/google/list',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/');
    });
///////////////////////////////////////////////////////////////////////////////////////////
let port = process.env.PORT;
if (port == null || port == "") {
    port = 4000;
}
app.listen(port);
