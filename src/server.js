const bodyParser = require('body-parser');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const passport = require('passport');

const server = require('express')();
const debug = require('debug')('cmyk:server');

const Strategy = require('./strategy');

// Redirect for HTTPS
server.use(function (req, res, next) {
    return next();
    // If https terminated by heroku, or express asserts the conn. is encrypted,
    // or the protocol matches https, then we're good!
    if (req.headers['x-forwarded-proto'] === SERVER.protocol ||
        req.connection.encrypted ||
        req.protocol === SERVER.protocol) {
        res.header(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        next();
    }
    else res.redirect(`${SERVER.protocol}://${req.get('host')}${req.url}`);
});

server.use(compression());
server.use(bodyParser.json());
server.use(cookieParser());
server.use(csrf({cookie: true}));
server.use(passport.initialize());

passport.use(new Strategy({secret: 'secret'}, function (request, user, done) {
  request.user = user;
  done();
}));

function withAuthenticatedUser (request, response, next) {
  passport.authenticate('cmyk', (err, user, info) =>
    ! user ?
      request.login(user, (err) =>
        err ?
          response.send(401)
        : next())
    : response.send(401)
  )
}

server.use('/', withAuthenticatedUser, function (req, res, next) {
  res.send({
    message: 'hello'
  });
});

server.use('/login', function (req, res, next) {
  var token = require('jsonwebtoken').sign({id: 123, role: 'admin'}, 'secret');
  res.cookie('authorization', token)
  res.send(200);
});

server.listen(3000);
