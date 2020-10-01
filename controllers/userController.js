const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/userModel');
const { roles } = require('../roles');

exports.grantAccess = function (action, resource) {
    return async (req, res, next) => {

        try {
            const permission = await roles.can(req.user.role)[action](resource);

            if (!permission.granted) {
                return res.status(401).json({
                    error: "You don't have enough permission to perform this action"
                });
            }

            next();
        } catch (err) {
            next(err);
        }

    }
}

exports.allowIfLoggedin = async (req, res, next) => {

    try {

        let user = res.locals.loggedInUser;
        if (!user) {
            return res.status(400).json({
                error: "You need to be logged in to access this route"
            });
        }

        req.user = user;
        next();

    } catch (err) {
        next(err);
    }

}

async function hashPassword(plainPassword) {
    let hashedPass = await bcrypt.hash(plainPassword, 10);
    return hashedPass;
}

async function verifyPassword(plainPass, hashedPass) {
    let verification = await bcrypt.compare(plainPass, hashedPass);
    return verification;
}

exports.signUp = async (req, res, next) => {

    try {

        let { email, password, role } = req.body;
        let exist = await User.find({ email: email }).exec();

        if (exist.length > 0) {
            return next(new Error('User against this email already exists...'));
        }

        let hashed = await hashPassword(password);
        let newUser = new User({
            _id: mongoose.Types.ObjectId(),
            email: email,
            password: hashed,
            role: role || 'basic'
        })

        let token = jwt.sign({ userId: newUser._id }, 'My Secret', {
            expiresIn: "1d"
        });

        newUser.accessToken = token;
        newUser.save();

        res.status(200).json({
            data: newUser,
            token
        })

    } catch (err) {
        next(err);
    }

}


exports.login = async (req, res, next) => {
    try {

        let { email, password } = req.body;
        let user = await User.find({ email: email }).exec();

        if (!user) {
            return next(new Error('Email doesnt exist...'));
        }

        let verify = await verifyPassword(password, user[0].password);
        if (!verify) {
            return next(new Error('Incorrect Password'));
        }

        let accessToken = jwt.sign({ userId: user[0]._id }, 'My Secret', {
            expiresIn: "1d"
        });

        await User.findByIdAndUpdate(user[0]._id, { accessToken: accessToken }).exec();

        res.status(200).json({
            user: { email: user[0].email, role: user[0].email },
            accessToken
        });

    } catch (err) {
        next(err);
    }
}

exports.getUser = async (req, res, next) => {
    try {
        let token = req.headers["x-access-token"];
        let { userId } = await jwt.verify(token, 'My Secret');

        if (!userId) {
            return next(new Error('Token is invalid...'));
        }

        let user = await User.findById(userId).exec();
        res.status(200).json({
            user: user
        });
    } catch (err) {
        next(err);
    }
}

exports.getUsers = async (req, res, next) => {
    try {
        let users = await User.find({}).exec();

        res.status(200).json({
            user: users
        });
    } catch (err) {
        next(err);
    }
}

exports.updateUser = async (req, res, next) => {
    try {

        let updatedObj = req.body;
        let token = req.headers['x-access-control'];
        let { userId } = await jwt.verify(token, 'My Secret');

        if (!userId) {
            return next(new Error('Invalid Token...'));
        }

        let updated = await User.findByIdAndUpdate(userId, { updatedObj }).exec();

        res.status(200).json({
            user: updated,
            message: 'User updated...'
        });

    } catch (err) {
        next(err);
    }
}

exports.deleteUsers = async (req, res, next) => {
    try {

        let token = req.headers['x-access-control'];
        let { userId } = await jwt.verify(token, 'My Secret');

        if (!userId) {
            return next(new Error('Invalid Token...'));
        }

        await User.findByIdAndDelete(userId).exec();

        res.status(200).json({
            user: null,
            message: 'User updated...'
        })


    } catch (err) {
        next(err);
    }
}