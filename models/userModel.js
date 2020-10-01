const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    _id: mongoose.ObjectId,
    email: {
        type: String,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: 'basic',
        enum: ['basic', 'supervisor', 'admin']
    },
    accessToken: {
        type: String,
        required: true
    }
});

module.exports = mongoose.model('User', UserSchema);