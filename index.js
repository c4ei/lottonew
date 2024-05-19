const express = require('express');
const mysql = require('mysql2');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const dotenv = require('dotenv').config();

const app = express();

// MySQL 연결 설정
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_DATABASE
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected...');
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.COOKIE_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new MySQLStore({
        host: process.env.DB_HOST,
        port: 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_DATABASE
    })
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  function(username, password, done) {
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
      if (err) return done(err);
      if (results.length === 0) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const sql = 'SELECT * FROM users WHERE id = ?';
  db.query(sql, [id], (err, results) => {
    done(err, results[0]);
  });
});

// 언어별 문자열을 저장하는 객체
const strings = {
    en: {
        title: 'Login',
        username: 'Username',
        password: 'Password',
        loginBtn: 'Login',
        backToMain: 'Back to main'
    },
    ko: {
        title: '로그인',
        username: '사용자 이름',
        password: '비밀번호',
        loginBtn: '로그인',
        backToMain: '메인으로 돌아가기'
    }
};

// 미들웨어 함수
function languageMiddleware(req, res, next) {
    const acceptLanguage = req.headers['accept-language'] || 'en';
    // 언어에 해당하는 문자열 객체를 요청 객체에 바인딩
    req.strings = strings[acceptLanguage] || strings['en'];
    next();
}

// Express 앱에 미들웨어 등록
app.use(languageMiddleware);



app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
  db.query(sql, [username, hashedPassword], (err, result) => {
    if (err) {
      return res.redirect('/error?message=' + encodeURIComponent('Error registering new user.'));
    }
    res.redirect('/login');
  });
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/error?message=' + encodeURIComponent('Invalid username or password.'),
  failureFlash: true
}));

// 라우트 핸들러에서 문자열 객체를 사용하여 렌더링
app.get('/login', (req, res) => {
    res.render('login', { title: req.strings.title ,
        username: req.strings.username,
        password: req.strings.password,
        loginBtn: req.strings.loginBtn,
        backToMain: req.strings.backToMain

    });
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.post('/submit-number', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/error?message=' + encodeURIComponent('You need to log in to submit a number.'));
  }

  const { numbers } = req.body;
  const userId = req.user.id;
  
  const sql = 'INSERT INTO user_buy (user_id, numbers) VALUES (?, ?)';
  db.query(sql, [userId, numbers.join(',')], (err, result) => {
    if (err) {
      return res.redirect('/error?message=' + encodeURIComponent('Error submitting number.'));
    }
    res.redirect('/');
  });
});

app.get('/', (req, res) => {
    res.render('lotto', { title: 'Lotto', user: req.user });
});

app.get('/error', (req, res) => {
  const errorMsg = req.query.message || 'An error occurred';
  res.render('error', { title: 'Error', errorMsg: errorMsg });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
