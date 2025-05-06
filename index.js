require("./utils.js");
require('dotenv').config();
const express = require('express');
const app = express();

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const fs = require('fs');
app.use("/p", express.static("./public"));

const port = process.env.PORT || 3000;


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)
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

app.get("/", function (req, res) {
    if (!req.session.authenticated) {
        var html = `
        <a href='/createUser'>Sign up</a>
        <a href='/login'>Log in</a>
        `;
        res.send(html);
    } else {
        var html = `
        <p>Hello, ${req.session.name}!</p>
        <a href="members">Go to Members Area</a>
        <a href="logout">Sign out</a>
        `;
        res.send(html);
    }

    
});

app.get('/createUser', (req, res) => {
    var html = `
    Create New User
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    var html = `
    Login
    <form action='/loggingIn' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
        var html = `<a href='/createUser'>Try again</a>`;
        for (detail of validationResult.error["details"]) {
            html += `<p>${detail.message}</p>`;
        }
        res.send(html);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loggingIn', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required().label('email');
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        var html = `<a href='/login'>Try again</a><p>${validationResult.error["details"][0].message}</p>`;
        res.send(html);
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();
    if (result.length != 1) {
        res.send("No user with that email found.<a href='/login'>Try again</a>");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.send("Invalid email/password combination.<a href='/login'>Try again</a>");
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    var random = Math.floor(Math.random() * 3) + 1;
    var html = `
    <h1>Hello, ${req.session.name}.</h1>
    <img src="${random == 1 ? 'p/butterflyfrog.jpg' 
        : random == 2 ? 'p/relaxedfrog.jpg'
        : 'p/tinyfrog.jpg'}" style='max-width:500px; max-height:500px;' alt="a frog">
    <a href="/logout">Sign out</a>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use(function (req, res) {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 