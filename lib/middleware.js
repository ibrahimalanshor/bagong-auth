const { TokenExpiredError, JsonWebTokenError, ...jwt } = require('jsonwebtoken')
const { AuthenticationError } = require('bagong').Exception

module.exports = async (req, res, next) => {
  try {
    const token = req.headers.authorization
    const key = req.key

    if (!token) throw new AuthenticationError('Token missing')

    await jwt.verify(token, key)

    next()
  } catch (err) {
    if (err instanceof TokenExpiredError || err instanceof JsonWebTokenError) {
      next(new AuthenticationError(err))
    } else {
      next(err)
    }
  }
}