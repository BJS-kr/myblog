const Joi = require('joi');

const registerSchema = Joi.object({
  nickname: Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
  pw: Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9]{4,30}$')),
  re_pw: Joi.ref('pw'),
});

const c = new Promise(function ab(nickname, pw, re_pw) {
  registerSchema
    .validateAsync({
      nickname: nickname,
      pw: pw,
      re_pw: re_pw,
    })
    .then((res) => {
      return true;
    })
    .catch((err) => {
      return false;
    });
})
  .then((res) => {
    return true;
  })
  .catch((err) => {
    return false;
  });

console.log(c);
