const jwt = require('jsonwebtoken');
const User = require('../schemas/user');
const privateKeys = require('../app.js');

module.exports = (req, res, next) => {
  const { authorization } = req.headers;
  const [tokenType, tokenValue] = authorization.split(' ');
  if (tokenValue === 'null') {
    next();
  }
  const { nickname } = jwt.decode(tokenValue);
  const privateKey = privateKeys.privateKeys[nickname];

  console.log(tokenType, tokenValue, nickname, privateKey);

  if (tokenType !== 'Bearer') {
    next();
  }

  try {
    jwt.verify(tokenValue, privateKey);
    User.findOne({ nickname })
      .exec()
      .then((user) => {
        res.locals.user = user;
        res.locals.token = tokenValue;
        next();
      });
  } catch (err) {
    console.log(err);
    next();
  }
};
