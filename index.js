const fp = require('fastify-plugin')
const path = require('path')
const tera = require('tuos-tera')

const plugin = async (fastify, opts, done) => {
  await fastify.register(tera, {
    dir: path.resolve(__dirname, 'plugins'),
    options: opts,
    order: [
      'jwt',
      'auth'
    ]
  })

  done()
}

module.exports = fp(plugin)
