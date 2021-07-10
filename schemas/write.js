const mongoose = require('mongoose');
const connection = mongoose.createConnection(
  'mongodb://localhost:27017/voyage',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    ignoreUndefined: true,
  }
);
const autoIncrement = require('mongoose-auto-increment');

autoIncrement.initialize(connection);

const { Schema } = mongoose;
const writeSchema = new Schema({
  pageNum: Number,
  title: {
    type: String,
    required: true,
  },
  desc: {
    type: String,
    required: true,
  },
  nickname: {
    type: String,
    required: true,
  },
  date: String,
});

writeSchema.plugin(autoIncrement.plugin, {
  model: 'Write',
  field: 'pageNum',
  startAt: 1,
  increment: 1,
});

module.exports = mongoose.model('Write', writeSchema);
