const passport = require('passport');

const SECRET = 'secret';

const Strategy = require('./Strategy');

passport.use(new Strategy({secret: SECRET}, function (request, user, done) {
  // request.user = user;
  done(null, user);
}));

passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((user, done) => done(null, user))

function withAuthenticatedUser (request, response, next) {
  passport.authenticate('cmyk', { session: false }, (err, user, info) =>
    ! user ? response.sendStatus(401)
    : request.login(user, (err) => err ? response.sendStatus(500) : next())
  )(request, response, next);
}

module.exports = {
  SECRET,
  withAuthenticatedUser
};
