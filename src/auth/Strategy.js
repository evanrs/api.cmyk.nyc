const BearStrategy = require('passport-http-bearer');
const jsonwebtoken = require('jsonwebtoken');
const result = require('lodash/object/result');

/**
 * @constructor
 * @param {Object} options an options map
 * @param {Function} verify the verification method
 */
class Strategy extends BearStrategy {
  constructor(options, verify) {
    super(function (request, token, done) {
      jsonwebtoken.verify(token, this._secret, (err, user) =>
        err ? this.fail(400, err) : verify(request, user, done))
    });

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
    let token =
      result(request.headers, 'authorization') ||
      result(request.session, 'authorization') ||
      result(request.cookies, 'authorization');

    if (! token) return this.fail(401);

    request.headers.authorization =
      /^Bearer/.test(token) ? token : `Bearer ${token}`;

    return super.authenticate(request);
  }
}

module.exports = Strategy;
