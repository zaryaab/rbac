// server/server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path')
const User = require('./models/userModel')
const routes = require('./routes/userRoute');

require("dotenv").config({
    path: path.join(__dirname,)
});

const app = express();

const PORT = process.env.PORT || 3000;

mongoose
    .connect('mongodb://localhost:27017/rbac', {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => {
        console.log('Connected to the Database successfully');
    });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(async (req, res, next) => {
    if (req.headers["x-access-token"]) {
        const accessToken = req.headers["x-access-token"];
        const { userId, exp } = await jwt.verify(accessToken, 'My Secret');

        // Check if token has expired
        if (exp < Date.now().valueOf() / 1000) {
            return res.status(401).json({ error: "JWT token has expired, please login to obtain a new one" });
        }
        res.locals.loggedInUser = await User.findById(userId);
        next();
    } else {
        next();
    }
});

app.use('/rbac', routes);

app.listen(PORT, () => {
    console.log('Server is listening on Port:', PORT)
})