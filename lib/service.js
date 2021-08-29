const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { AuthenticationError } = require('bagong').Exception

class AuthService {

  async register(data)  {
    data.password = await bcrypt.hash(data.password, 10)

    const user = await this.create(data)
    const token = await this.attempt(user)

    return token
  }

  async login({ username, password }) {
    try {
      const user = await this.search({ username }).lean()

      if (!user) {
        throw 'User Not Found'
      }

      const match = await bcrypt.compare(password, user.password)

      if (!match) {
        throw 'Password incorrect'
      }

      const token = this.attempt(user)

      return token
    } catch (err) {
      throw new AuthenticationError(err)
    }
  }

  async attempt(user) {
    const payload = {
      username: user.username,
      password: user.password,
    }

    const token = await jwt.sign(payload, process.env.APP_KEY, {
      expiresIn: '1h'
    })

    return token
  }

}

module.exports = new AuthService