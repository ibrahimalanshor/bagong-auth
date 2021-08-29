const { TokenExpiredError, ...jwt } = require('jsonwebtoken')
const { AuthenticationError } = require('bagong').Exception

class AuthMiddleware {

  async check (req, res, next) {
    try {
      const token = req.headers.authorization
      const key = this.key

      if (!token) throw new AuthenticationError('Token missing')

      await jwt.verify(token, key)

      next()
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        next(new AuthenticationError(err))
      } else {
        next(err)
      }
    }
  }

}

module.exports = AuthMiddleware