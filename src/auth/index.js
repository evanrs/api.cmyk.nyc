const passport = require('passport');
const jsonwebtoken = require('jsonwebtoken');
const GithubStrategy = require('passport-github');

const Strategy = require('./Strategy');


const SECRET = 'secret';
const SUPER_SECRET = 'much more secret'
const COOKIE = {
  secure: process.env.NODE_ENV === 'production',
  domain: process.env.COOKIE_DOMAIN
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new Strategy(
    {secret: SUPER_SECRET},
    (request, user, done) => done(null, user)));

module.exports = {
  SECRET,
  COOKIE,
  // route decorators
  requireUser (request, response, next) {
    passport.authenticate('cmyk', { session: false }, (err, user, info) =>
      ! user ? response.sendStatus(401)
      : request.login(user, (err) => err ? response.sendStatus(500) : next())
    )(request, response, next);
  },
  // Providers
  github: {
    connect(server) {
      passport.use(
        new GithubStrategy({
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: `${server.locals.domain}/auth/github/callback`,
            scope: ['user', 'gist']
          },
          (accessToken, refreshToken, profile, done) =>
            done(null, {
              accessToken,
              refreshToken,
              profile: {...profile, _raw: false}})));

      server.get('/auth/github', saveReferrer, passport.authenticate('github'));
      server.get('/auth/github/callback', this.handleCallback, loadReferrer);
    },

    handleCallback (request, response, next) {
      passport.authenticate('github', function (err, user, info) {
        if (! err && user) try {
          request.session.authorization = jsonwebtoken.sign(user, SUPER_SECRET);
        } catch (e) { err = err || e }

        next(err);
      })(request, response, next);
    }
  }
}

function saveReferrer(req, res, next) {
  req.session.referrer = req.get('referrer');
  next();
}

function loadReferrer(req, res, next) {
  let {referrer} = req.session;
  req.session.referrer = void 0;
  req.session.save();

  res.redirect(referrer || '/')
}
