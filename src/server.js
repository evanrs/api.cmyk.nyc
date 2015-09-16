const bodyParser = require('body-parser');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const passport = require('passport');

const debug = require('debug')('cmyk:server');
const server = require('express')();

const PORT = process.env.PORT || 3000;
const {SECRET, withAuthenticatedUser} = require('./auth');

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

server.use(compression());
server.use(bodyParser.json());
server.use(cookieParser(SECRET, {
  secure: false,
  domain: '.cmyk.nyc'
}));
server.use(csrf({cookie: true}));
server.use(passport.initialize());


server.use('/sanity', (req, res) => res.send({message: 'you\'re OK'}));


server.use('/login', function (req, res, next) {
  var token = require('jsonwebtoken').sign({id: 123, role: 'admin'}, SECRET);
  res.cookie('authorization', token);
  res.sendStatus(200);
});

server.use('/', withAuthenticatedUser, function (req, res, next) {
  res.send(req.user);
  next();
});

var connection = server.listen(PORT, () =>
  debug(`Listening at port ${connection.address().port}`));
