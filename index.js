require("./utils.js");
require('dotenv').config();
const express = require('express');
const app = express();
const url = require("url");
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const fs = require('fs');
app.use("/p", express.static("./public"));
app.set('view engine', 'ejs'); 

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/404"}
];

app.use("/", (req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
})

const port = process.env.PORT || 3000;


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)
const Joi = require("joi");

app.use(express.urlencoded({ extended: false }));

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == "admin") {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized To Access This Page!"});
        return;
    }
    else {
        next();
    }
}

app.get("/", function (req, res) {
    if (!req.session.authenticated) {
        res.render("index", { authenticated: false});
    } else {
        res.render("index", { authenticated: true, name: req.session.name});
    }

    
});

app.get('/createUser', (req, res) => {
    res.render("createUser");
});


app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(100).required(),
            email: Joi.string().max(20).email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate( {name, email, password}, {abortEarly: false} );
    if (validationResult.error != null) {
        let details = [];
        for (detail of validationResult.error["details"]) {
            details.push(detail.message);
        }
        res.render("submitUser", { details: details});
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user"});
    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = "user";

    res.redirect('/members');
});

app.post('/loggingIn', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required().label('email');
    const validationResult = schema.validate(email);
    let error = "";
    if (validationResult.error != null) {
        error = validationResult.error["details"][0].message;
        res.render("loggingIn", { error: error});
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1, user_type: 1 }).toArray();
    if (result.length != 1) {
        error = "No user with that email found";
        res.render("loggingIn", { error: error});
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;
        res.redirect('/members');
        return;
    }
    else {
        error = "Invalid email/password combination";
        res.render("loggingIn", { error: error});
        return;
    }
});

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        res.render("frogs", { name: req.session.name});
    } else {
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ name: 1, _id: 1, user_type: 1 }).toArray();
    res.render("admin", { users: result});
});

app.get('/promote', async (req, res) => {
    await userCollection.updateOne({ name: req.query.name }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

app.get('/demote', async (req, res) => {
    await userCollection.updateOne({ name: req.query.name }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

app.use(function (req, res) {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 