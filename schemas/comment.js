const mongoose = require('mongoose');
const { Schema } = mongoose;

const commentSchema = new Schema({
  nickname: {
    type: String,
    required: true,
  },
  comment: {
    type: String,
    required: true,
  },
  pageNum: {
    type: Number,
    required: true,
  },
});

module.exports = mongoose.model('Comment', commentSchema);
