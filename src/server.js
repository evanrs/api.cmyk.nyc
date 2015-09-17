const bodyParser = require('body-parser');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const csrf = require('csurf');
const session = require('express-session');
const passport = require('passport');


const auth = require('./auth');
const debug = require('debug')('cmyk:server');
const server = require('express')();

server.locals.port = process.env.PORT || 3000;
server.locals.domain =
  process.env.NODE_ENV === 'production' ?
    'https://api.cmyk.nyc' : `http://localhost:${server.locals.port}`;

// Redirect for HTTPS
server.set('trust proxy', true);
server.use(function (req, res, next) {
  if (process.env.NODE_ENV !== 'production')
    return next();

  // If https terminated by heroku, or express asserts the conn. is encrypted,
  // or the protocol matches https, then we're good!
  if (req.secure ||
      req.headers['x-forwarded-proto'] === 'https' ||
      req.connection.encrypted ||
      req.protocol === 'https') {
    res.header(
      'Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    next();
  }
  else
    res.redirect(`https://${req.get('host')}${req.url}`);
});

server.use(cors({origin: true, credentials: true}));
server.use(compression());
server.use(bodyParser.json());
server.use(
  session({
    cookie: auth.COOKIE,
    secret: auth.SECRET,
    saveUninitialized: false
}));
server.use(cookieParser(auth.SECRET, auth.COOKIE));
server.use(csrf({cookie: true}));
server.use(passport.initialize());
server.use(passport.session());

auth.github.connect(server);

server.get('/logout', function logout (request, response) {
  request.session.destroy(function (err) {
    response.redirect(request.get('referrer') || '/');
  });
});

server.get('/profile', auth.requireUser, function (req, res, next) {
  res.json(req.user.profile);
  next();
});

server.get('/', auth.requireUser, function (req, res, next) {
  res.json(req.user);
  next();
});

var connection = server.listen(server.locals.port, () =>
  debug(`Listening at port ${connection.address().port}`));
