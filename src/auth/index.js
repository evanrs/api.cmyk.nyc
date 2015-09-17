const passport = require('passport');
const jsonwebtoken = require('jsonwebtoken');
const GithubStrategy = require('passport-github');

const Strategy = require('./Strategy');


const SECRET = 'secret';
const SUPER_SECRET = 'much more secret'
const COOKIE = {
  domain: process.env.COOKIE_DOMAIN,
  maxAge: 1000 * 60 * 60 * 24 * 14,
  path: '/',
  secure: process.env.NODE_ENV === 'production'
}

const cache = {};

passport.serializeUser((user, done) => {
  let {id} = user.profile;
  cache[id] = user;

  done(null, id);
});
passport.deserializeUser((id, done) => {

  done(null, cache[id]);
});

passport.use(
  new Strategy(
    {secret: SUPER_SECRET},
    (req, user, done) => done(null, user)));

function saveReferrer(req, res, next) {
  req.session.referrer = req.get('referrer');
  next();
}

function loadReferrer(req, res) {
  let {referrer} = req.session;
  req.session.referrer = void 0;
  req.session.save();
  req.xhr ? res.json(req.user) : res.redirect(referrer || '/');
}

const auth =
module.exports = {
  SECRET,
  COOKIE,
  // route decorators
  requireUser (req, res, next) {
    passport.authenticate('cmyk', (err, user, info) =>
      ! user ? res.sendStatus(401)
      : req.login(user, (err) =>
          err ? res.sendStatus(500) : next())
    )(req, res, next);
  },

  validate (req, res, next) {
    passport.authenticate('cmyk', (err, user, info) => {
      let validation = '';
      if (user) {
        let {profile: {displayName, _json: {avatar_url}}} = user;
        validation = JSON.stringify({displayName, avatar_url});
      }
      res.cookie('authorized', validation, {domain: COOKIE.domain})
      next(err);
    })(req, res, next)
  },

  logout(req, res, next) {
    req.logout();
    req.session.destroy((err) => next(err));
  },

  handleError (err, req, res, next) {
    debugger;
  },

  connect(server) {
    server.get(
      '/auth/validate', auth.validate, auth.handleError, (req, res) => res.send(200));
    server.get(
      '/logout',
      auth.logout,
      auth.validate,
      auth.handleError,
      (req, res, next) =>
        req.xhr ? res.send(200) : res.redirect(req.get('referrer') || '/')
    );
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
      server.get('/auth/github/callback', this.handleCallback, auth.validate, loadReferrer);
    },

    handleCallback (req, res, next) {
      passport.authenticate('github', function (err, user, info) {
        if (! err && user) try {
          req.session.authorization = jsonwebtoken.sign(user, SUPER_SECRET);
          return req.session.save((err) => next(err));
        } catch (e) { err = err || e }

        next(err);
      })(req, res, next);
    }
  }
}
