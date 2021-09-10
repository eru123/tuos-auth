const fp = require('fastify-plugin')

const plugin = async function (fastify, opts, done) {
  const Tokens = fastify.mongoose.models.Tokens

  const defaultOpts = { secret_token: 'default_secret_token' }
  const options = opts.jwt || (() => {
    console.log('[PLUGIN] jwt: Using default secret_token')
    return defaultOpts
  })()
  const secretToken = options.secret_token

  await fastify.register(require('fastify-jwt'), { secret: secretToken })

  fastify.decorateRequest('authenticated', false)
  fastify.decorateRequest('token', null)

  const prepareAuth = async (req, res) => {
    try {
      const token = String(req.headers.authorization).split(' ')[1]
      if (!token) { return }
      req.token = token

      const userId = fastify.jwt.decode(token)._id
      const record = await Tokens.findOne({ user_id: userId, token })
      if (record) {
        fastify.jwt.verify(token, null, (err, decoded) => {
          if (!err) {
            req.authenticated = true
            req.user = decoded
          } else console.log(`[JWT] ${err.name}: ${err.message}`)
        })
      }
    } catch (e) {
      console.log(`[JWT] ${e.name}: ${e.message}`)
    }
  }

  await fastify.addHook('preValidation', prepareAuth)

  const authenticate = async (req, res) => {
    if (!req.authenticated && !res.sent) { return res.status(401).send({ type: 'error', message: 'Unauthorized' }) }
  }

  if (!('auth' in fastify)) fastify.decorate('auth', authenticate)
  if (!('prepareAuth' in fastify)) fastify.decorate('prepareAuth', prepareAuth)

  done()
}

module.exports = fp(plugin)
