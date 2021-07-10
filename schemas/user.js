const mongoose = require('mongoose');
const { Schema } = mongoose;

const registrationSchema = new Schema({
  nickname: {
    type: String,
    required: true,
  },
  salt: {
    type: String,
    required: true,
  },
  hashedPassword: {
    type: String,
    required: true,
  },
});

module.exports = mongoose.model('User', registrationSchema);
