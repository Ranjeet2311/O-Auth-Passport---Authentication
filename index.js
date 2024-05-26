import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import GoogleStrategy from 'passport-google-oauth2';
import env from 'dotenv';

const app = express();
const port = 3000;
const saltRounds = 12;
env.config(); //set up environ variable

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 365,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

console.log(`process.env.PASSWORD :: `, process.env.PASSWORD);

const db = new pg.Client({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT,
});

db.connect();

app.get('/', (req, res) => {
  res.render('home.ejs');
});

app.get('/login', (req, res) => {
  res.render('login.ejs');
});

app.get('/register', (req, res) => {
  res.render('register.ejs');
});

app.get('/secrets', (req, res) => {
  console.log(`Secret req 1 : `, req.user);
  console.log(`Secret req 1 : `, req);
  if (req.isAuthenticated()) {
    res.render('secrets.ejs');
  } else {
    res.render('login.ejs');
  }
});

app.post('/register', async (req, res) => {
  const inputEmail = req.body.username;
  const inputPassword = req.body.password;

  const checkEmail = await db.query('SELECT * FROM users WHERE email = $1', [
    inputEmail,
  ]);

  console.log(`checkEmail 1 : `, checkEmail);

  try {
    if (checkEmail.rows.length > 0) {
      res.send(
        'Account already exists, try loging-in with correct email & password'
      );
    } else {
      bcrypt.hash(inputPassword, saltRounds, async (error, hash) => {
        if (error) {
          console.log('bcrypt : ', error);
        } else {
          const result = await db.query(
            'INSERT INTO users (email, password ) VALUES ($1, $2) RETURNING *',
            [inputEmail, hash]
          );
          console.log(`result 1 :: `, result);

          const user = result.rows[0];

          req.login(user, (err) => {
            console.log(err);
            res.redirect('/secrets');
          });

          // res.render('secrets.ejs');
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);
app.get(
  '/auth/google/secrets',
  passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
  })
);

app.get('/logout', (req, res) => {
  req.logout((error) => {
    if (error) console.log(err);
    res.redirect('/');
  });
});

app.get('/secret', (req, res) => {
  res.redirect('/secrets');
}); //another redirect in case of wrong word

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
  })
);

// ----Authenticating the user----------------

passport.use(
  'local',
  new Strategy(async function verify(username, password, cb) {
    try {
      const checkUser = await db.query('SELECT * FROM users WHERE email = $1', [
        username,
      ]);
      const user = checkUser.rows[0];
      bcrypt.compare(password, user.password, async (error, result) => {
        console.log(`hash :: `, result);
        if (error) {
          // console.log('bcrypt : ', error);
          cb(error);
        } else {
          if (user.length != 0 && result) {
            return cb(null, user);
            // res.render('secrets.ejs');
          } else {
            // res.send(
            //   'Something wen wrong, please enter correct email & password!'
            // );
            return cb(null, false);
          }
        }
      });
    } catch (error) {
      console.log(error);
      return cb('No user found');
    }
  })
);

// ----Authenticating the user with google -OAuth----------------

passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
      userProfile: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    async (accessToken, refreshToken, profile, cb) => {
      // console.log('profile 1 :: ', profile);

      try {
        const result = await db.query('SELECT * FROM users where email = $1', [
          profile.email,
        ]);

        if (result.rows.length === 0) {
          const newUser = await db.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) ',
            [profile.email, 'google']
          );
          cb(null, newUser.rows[0]);
        } else {
          cb(null, result.rows[0]);
        }
      } catch (error) {
        cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
