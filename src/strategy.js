const BearStrategy = require('passport-http-bearer');
const jsonwebtoken = require('jsonwebtoken');

/**
 * @constructor
 * @param {Object} options an options map
 * @param {Function} verify the verification method
 */
class Strategy extends BearStrategy {
  constructor(options, verify) {
    super((request, token, done) =>
      jsonwebtoken.verify(token, this._secret, (err, user) => {
        try {
          user = JSON.parse(user)
        }
        catch (catchErr) {
          return this.fail(400, err || catchErr)
        }

        return verify(request, user, done);
      }
    ));

    this.name = 'cmyk'
    this._secret = options.secret;
    this._passReqToCallback = true;
  }

  /**
   * Authenticate request based on the contents of the `Authorization` header,
   * or an `authorization` cookie. Will accept token without Bearer prefix.
   * @param  {Object} request the request object
   * @api protected
   */
  authenticate(request) {
    let token = req.headers.authorization || req.cookies['authorization'];

    if (! token) return this.fail(401);

    req.headers.authorization =
      /^Bearer/.test(token) ? token : `Bearer ${token}`;

    return super(request);
  }
}

module.exports = Strategy;
