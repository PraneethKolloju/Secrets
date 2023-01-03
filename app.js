//jshint esversion:6
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const exp = require('constants');
const mongoose = require('mongoose');
const app = express();
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
require('dotenv').config();
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
    secret: 'thisismysecret',
    resave: false,
    saveUninitialized: true
}));

mongoose.set('strictQuery', true); // to avoid depreciation warning
app.use(passport.initialize()); // initializing passport 
app.use(passport.session());  //initiating the session



mongoose.connect('mongodb://0.0.0.0:27017/userDB', { useNewUrlParser: true });




//This is the Encrypted Mongoose DB Schema
const userSchema = mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: String
});
//Below 2 lines of code makes the DB encrypted



userSchema.plugin(passportLocalMongoose); //using passpostlocalMongoose
userSchema.plugin(findOrCreate);
const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (User, done) {
    done(null, User);
});
passport.deserializeUser(function (User, done) {
    done(null, User);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfieURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, User) {
            return cb(err, User);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APPID,
    clientSecret: process.env.APPSECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, User) {
            return cb(err, User);
        });
    }
));



app.get('/', function (req, res) {
    res.render('home');
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/register', function (req, res) {
    res.render('register');
});

app.get('/login', function (req, res) {
    res.render('login');
});

app.get('/secrets', function (req, res) {
    User.find({ 'secret': { $ne: null } }, function (err, founduser) {
        if (err) {
            console.log(err);
        } else {
            res.render('secrets', { listofusers: founduser });
        }
    })
});

app.get('/logout', function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            console.log('logged out');
        }
    });
    res.redirect('/');
});

app.get('/submit', function (req, res) {
    res.render('submit');
})

app.post('/register', function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
            })
        }
    })
})

app.post('/login', function (req, res) {
    const user = new User({
        email: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
            })
        }
    })
});

app.post('/submit', function (req, res) {
    const fetchedsecret = req.body.secret;
    console.log(req.user._id);
    User.findById(req.user._id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            foundUser.secrets = fetchedsecret;
            foundUser.save(function () {
                res.redirect("/secrets");
            })
        }

    });
})



app.listen(3000, function (req, res) {
    console.log('3000 started');
});
