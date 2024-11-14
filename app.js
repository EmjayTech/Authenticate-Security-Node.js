//jshint esversion:6
require("dotenv").config();
const express  = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
// It is for salting of passwords to hash (Step 4)
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// It is for hashing of password (Step 3) const md5 = require("md5");
// It is for encrypting of password using cipher (Step 2) const encrypt = require("mongoose-encryption");


const app = express();


app.use(express.static("public"));
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB").then(() => {
    console.log("MongoDB is connected")
}).catch((err) => {
    console.log(err.message)
});




const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Encryption code
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// passport.serializeUser(function(user, done) {
//     done(null, user.id);
// });
// passport.deserializeUser(function(id, done) {
//     User.findById(id, function(err, user) {
//         done(err, user);
//     });
// });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
});
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"]})
);
app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        res.redirect("/secrets");
    }
);
app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

// app.post("/register", (req, res) => {
//     const newUser = new User({
//         email: req.body.username,
//         password: md5(req.body.password)
//     })
//     newUser.save();
//     if(newUser){
//         res.render("secrets")
//     } else{
//         console.log("Unable to register the user")
//     }
// });

// to use bcrypt to protect password
// app.post("/register", (req, res) => {
//      bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
//     const newUser = new User({
//         email: req.body.username,
//         password: hash
//     })
//     newUser.save();
//     if(newUser){
//         res.render("secrets")
//     } else{
//         console.log("Unable to register the user")
//     }
//    } )
        
//     });

// Using hash and salting to protect passport
// app.post("/login", async(req, res) => {
//     const username = req.body.username;
//     const password = req.body.password;
//     //using hash password to log in: const password = md5(req.body.password);
//     const foundUser = await User.findOne({email: username});
//     if(foundUser){
//         // if (foundUser.password === password)
//         bcrypt.compare(password, foundUser.password, (err, result) => {
//             if(result === true){
//                 res.render("secrets");
//             } else {
//                 console.log("Error");
//             }
//         });
            
//         } 
//     });
app.get("/secrets", async(req, res) => {
   const foundUsers= await User.find({"secret": {$ne: null}}) 
        if(!foundUsers){
            console.log(err);
        } else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
 });


app.get("/submit", (req, res) => {
    if (req.isAuthenticated()){
        res.render("submit")
    } else {
        res.redirect("/login");
    }
});
app.post("/submit", async(req, res) => {
    const submittedSecret = req.body.secret;
    const foundUser = await User.findById(req.user.id);
    if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save();
        res.redirect("/secrets");
    } else {
        console.log("Error detected!");
    }
});

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if(err){
            return next(err);
        }
        res.redirect("/");
    });
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if(err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});













const port = process.env.PORT || 3000;

app.listen(port, () => {
    console.log("Server is connected at port 3000");
});