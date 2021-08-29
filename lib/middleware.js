const { TokenExpiredError, ...jwt } = require('jsonwebtoken')
const { AuthenticationError } = require('bagong').Exception

module.exports = async (req, res, next) => {
  try {
    const token = req.headers.authorization
    const key = process.env.APP_KEY

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