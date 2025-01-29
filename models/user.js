const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/backend')

const userSchema = new mongoose.Schema({
    username: String,
    name: String,
    email: String,
    password: String,
    age: Number,
    post: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'post'
    }]
});

module.exports = mongoose.model('user', userSchema); 