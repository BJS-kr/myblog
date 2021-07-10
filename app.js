const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const logger = require('morgan');
const crypto = require('crypto');
const Write = require('./schemas/write');
const User = require('./schemas/user');
const Comment = require('./schemas/comment');
const authMiddleware = require('./middlewares/auth-middleware');

const connect = require('./schemas');
connect();

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const nicknames = {};
let nickname = null;
const privateKeys = {};
let vali = false;

exports.privateKeys = privateKeys;

const registerSchema = Joi.object({
  nickname: Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
  pw: Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9]{4,30}$')),
  re_pw: Joi.ref('pw'),
});

app
  .route('/register')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    res.write(`<script>fetch('http://diethell.shop/register',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/registera')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app
  .route('/registera')
  .get((req, res) => {
    if (nicknames[nickname]) {
      res.write(
        '<script type="text/javascript">alert("already logged in");</script>'
      );
      res.write(`<script>window.location.href='/'</script>`);
    } else {
      res.render('register');
    }
  })
  .post(async (req, res) => {
    try {
      const { nickname, pw, re_pw } = await registerSchema.validateAsync(
        req.body
      );

      const isNicknameExists = await User.findOne({ nickname });

      if (isNicknameExists) {
        res.write(
          '<script type="text/javascript">alert("nickname already exists!");</script>'
        );
        res.write('<script>window.location.href="/register"</script>');
      } else if (!pw.indexOf(nickname)) {
        res.write(
          '<script type="text/javascript">alert("don\'t include your nickname in password!");</script>'
        );
        res.write('<script>window.location.href="/register"</script>');
      } else {
        const salt = crypto.randomBytes(64).toString('base64');
        const hashedPassword = crypto
          .pbkdf2Sync(pw, salt, 98672, 64, 'sha512')
          .toString('base64');
        await User.create({ nickname, salt, hashedPassword });
        res.status(201).render('login');
      }
    } catch (err) {
      console.log(err);
      res.write(
        '<script type="text/javascript">alert("stick to the registration rules!");</script>'
      );
      res.write('<script>window.location.href="/register"</script>');
    }
  });

app
  .route('/register/:pageNum')
  .get((req, res) => {
    const { pageNum } = req.params;
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    res.write(`<script>fetch('http://diethell.shop/register/${pageNum}',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/registera/${pageNum}')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app
  .route('/registera/:pageNum')
  .get((req, res) => {
    const { pageNum } = req.params;
    if (nicknames[nickname]) {
      res.write(
        '<script type="text/javascript">alert("already logged in");</script>'
      );
      res.write(`<script>window.location.href='/detail/${pageNum}'</script>`);
    } else {
      res.render('register', { pageNum: pageNum });
    }
  })
  .post(async (req, res) => {
    const { pageNum } = req.params;
    try {
      const { nickname, pw, re_pw } = await registerSchema.validateAsync(
        req.body
      );

      const isNicknameExists = await User.findOne({ nickname });

      if (isNicknameExists) {
        res.write(
          '<script type="text/javascript">alert("nickname already exists!");</script>'
        );
        res.write(
          `<script>window.location.href="/register/${pageNum}"</script>`
        );
      } else if (!pw.indexOf(nickname)) {
        res.write(
          '<script type="text/javascript">alert("don\'t include your nickname in password!");</script>'
        );
        res.write('<script>window.location.href="/register"</script>');
      } else {
        const salt = crypto.randomBytes(64).toString('base64');
        const hashedPassword = crypto
          .pbkdf2Sync(pw, salt, 98672, 64, 'sha512')
          .toString('base64');
        await User.create({ nickname, salt, hashedPassword });
        res.status(201).render('login', { pageNum: pageNum });
      }
    } catch (err) {
      console.log(err);
      res.write(
        '<script type="text/javascript">alert("stick to the registration rules!");</script>'
      );
      res.write(`<script>window.location.href="/register/${pageNum}"</script>`);
    }
  });

app
  .route('/login')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    res.write(`<script>fetch('http://diethell.shop/login',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/logina')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app
  .route('/logina')
  .get((req, res) => {
    if (nicknames[nickname]) {
      res.write(
        '<script type="text/javascript">alert("already logged in");</script>'
      );
      res.write(`<script>window.location.href='/'</script>`);
    } else {
      res.render('login');
    }
  })
  .post(async (req, res) => {
    const { nickname, pw } = req.body;
    const target = await User.findOne({ nickname });
    const salt = target.salt;
    const storedPassword = target.hashedPassword;
    const hashedPassword = crypto
      .pbkdf2Sync(pw, salt, 98672, 64, 'sha512')
      .toString('base64');
    const isNicknameExists = await User.findOne({ nickname });

    if (!isNicknameExists || storedPassword !== hashedPassword) {
      res.write(
        '<script type="text/javascript">alert("invalid nickname or password!");</script>'
      );
      res.write('<script>window.location.href="/login"</script>');
    } else {
      const nickname = isNicknameExists.nickname;
      const privateKey = crypto.randomBytes(64).toString('base64');
      const token = jwt.sign(
        {
          nickname: nickname,
          iat: Math.floor(Date.now() / 1000) - 30,
        },
        privateKey,
        { expiresIn: '1h' },
        { algorithm: 'RS256' }
      );
      privateKeys[nickname] = privateKey;
      nicknames[nickname] = token;
      res.write(`<script>localStorage.setItem('token','${token}')</script>`);
      res.write('<script>location.href="/"</script>');
    }
  });

app
  .route('/login/:pageNum')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    const { pageNum } = req.params;
    res.write(`<script>fetch('http://diethell.shop/login/${pageNum}',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/logina/${pageNum}')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }
    res.send();
  });

app
  .route('/logina/:pageNum')
  .get((req, res) => {
    const { pageNum } = req.params;
    if (nicknames[nickname]) {
      res.write(
        '<script type="text/javascript">alert("already logged in");</script>'
      );
      res.write(`<script>window.location.href='/'</script>`);
    } else {
      res.render('login', { pageNum: pageNum });
    }
  })
  .post(async (req, res) => {
    const { pageNum } = req.params;
    const { nickname, pw } = req.body;
    const target = await User.findOne({ nickname });
    const salt = target.salt;
    const storedPassword = target.hashedPassword;
    const hashedPassword = crypto
      .pbkdf2Sync(pw, salt, 98672, 64, 'sha512')
      .toString('base64');
    const isNicknameExists = await User.findOne({ nickname });

    if (!isNicknameExists || storedPassword !== hashedPassword) {
      res.write(
        '<script type="text/javascript">alert("invalid nickname or password!");</script>'
      );
      res.write(`<script>location.href="/login/${pageNum}"</script>`);
    } else {
      const nickname = isNicknameExists.nickname;
      const privateKey = crypto.randomBytes(64).toString('base64');
      const token = jwt.sign(
        {
          nickname: nickname,
          iat: Math.floor(Date.now() / 1000) - 30,
        },
        privateKey,
        { expiresIn: '1h' },
        { algorithm: 'RS256' }
      );
      privateKeys[nickname] = privateKey;
      nicknames[nickname] = token;
      res.write(`<script>localStorage.setItem('token','${token}')</script>`);
      res.write(`<script>location.href="/detail/${pageNum}"</script>`);
    }
  });

app
  .route('/logout')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    res.write(`<script>fetch('http://diethell.shop/logout',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/logouta')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app.get('/logouta', (req, res) => {
  delete privateKeys[nickname];
  delete nicknames[nickname];
  res.write(`<script>localStorage.clear();</script>`);
  res.write('<script>window.location.href="/"</script>');
});

app
  .route('/logout/:pageNum')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    const { pageNum } = req.params;
    res.write(`<script>fetch('http://diethell.shop/logout/${pageNum}',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/logouta/${pageNum}')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app.get('/logouta/:pageNum', (req, res) => {
  const { pageNum } = req.params;
  delete privateKeys[nickname];
  delete nicknames[nickname];
  nickname = null;
  res.write(`<script>localStorage.clear();</script>`);
  res.write(`<script>window.location.href="/detail/${pageNum}"</script>`);
});

app.post('/comment/:pageNum/:nickname', async (req, res) => {
  const { pageNum, nickname } = req.params;
  const { comment } = req.body;
  await Comment.create({ nickname, comment, pageNum });
  res.redirect(`/detail/${pageNum}`);
});

app
  .route('/update_comment/:pageNum/:id/:nickname')
  .get(async (req, res) => {
    const { id, pageNum, nickname } = req.params;
    const target = await Comment.findById(id);
    const targetComment = target.comment;
    const content = await Write.findOne({ pageNum });
    const comment = await Comment.find({ pageNum });

    res.render('comment_update', {
      id: id,
      targetComment: targetComment,
      content: content,
      comment: comment,
      nickname: nickname,
    });
  })
  .post(async (req, res) => {
    const { id, pageNum } = req.params;
    const { comment } = req.body;
    await Comment.findByIdAndUpdate(id, { comment: comment });
    res.redirect(`/detail/${pageNum}`);
  });

app.get('/del_cmt_confirm/:pageNum/:id', (req, res) => {
  const { id, pageNum } = req.params;
  res.write(`<script>if (window.confirm("do you really want to delete?")) {
    window.location.href='/delete_comment/${pageNum}/${id}';
  } else {
    window.location.href='/detail/${pageNum}';
  }</script>`);
});

app.get('/delete_comment/:pageNum/:id', async (req, res) => {
  const { id, pageNum } = req.params;
  await Comment.findByIdAndDelete(id);
  res.redirect(`/detail/${pageNum}`);
});

app
  .route('/write/:nickname')
  .get((req, res) => {
    const { nickname } = req.params;
    res.render('write', { nickname: nickname });
  })
  .post(async (req, res) => {
    const { nickname } = req.params;
    const { title, desc } = req.body;

    if (title.slice(0, 3) === '(공지)') {
      if (nickname !== 'juinjang') {
        res.write(
          '<script type="text/javascript">alert("notions can only be written by administrator");</script>'
        );
        res.write(`<script>window.location.href="/write/${nickname}"</script>`);
      }
    }

    const date = new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
    await Write.create({
      title,
      desc,
      nickname,
      date,
    });
    res.redirect('/');
  });

app
  .route('/detail/:pageNum')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    const { pageNum } = req.params;
    res.write(`<script>fetch('http://diethell.shop/detail/${pageNum}',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/detaila/${pageNum}')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }

    res.send();
  });

app.get('/detaila/:pageNum', async (req, res) => {
  const { pageNum } = req.params;
  const content = await Write.findOne({ pageNum });
  const comment = await Comment.find({ pageNum });
  let loginStatus = false;

  if (nickname) {
    loginStatus = true;
  }

  res.render('detail', {
    content: content,
    comment: comment,
    nickname: nickname,
    loginStatus: loginStatus,
  });
});

app
  .route('/update/:pageNum')
  .get(async (req, res) => {
    const { pageNum } = req.params;
    const content = await Write.findOne({ pageNum });
    res.render('update', { content: content });
  })
  .post(async (req, res) => {
    const { pageNum } = req.params;
    const { title, desc } = req.body;

    await Write.updateMany({ pageNum }, { $set: { title: title, desc: desc } });
    res.redirect(`/detail/${pageNum}`);
  });

app.get('/delete/:pageNum', async (req, res) => {
  const { pageNum } = req.params;
  await Write.deleteOne({ pageNum });
  res.redirect('/');
});

app
  .route('/')
  .get((req, res) => {
    const phrase = '`Bearer ${localStorage.getItem("token")}`';
    res.write(`<script>fetch('http://diethell.shop/',{
      method:'POST',
      headers:{
        authorization: ${phrase}
      }
    }).then(res => window.location.href = '/home')
    </script>`);
  })
  .post(authMiddleware, (req, res) => {
    nickname = null;
    if (res.locals.user) {
      nickname = res.locals.user.nickname;
    }
    vali = true;
    res.send();
  });

app.get('/home', async (req, res) => {
  if (!vali) {
    res.redirect('/');
  }
  const list = await Write.find().sort('pageNum');
  let loginStatus = false;
  if (nickname) {
    loginStatus = true;
  }
  vali = false;
  res.render('index', {
    title: 'Node.JS',
    list: list,
    nickname: nickname,
    loginStatus: loginStatus,
  });
});

module.exports = app;
