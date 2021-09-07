const fp = require('fastify-plugin')
const plugin = async function(fastify, opts, done) {
  const h = require('./handler')(fastify)

  fastify.post('/api/auth/register', h.create)
  fastify.post('/api/auth/login', h.login)
  fastify.delete('/api/auth/logout', h.logout)
  fastify.delete('/api/auth/logout/all', h.logouts)
  fastify.delete('/api/auth/logout/session/:id', h.logoutSession)
  fastify.get('/api/auth/session',h.session)
  fastify.get('/api/auth/session/:id', h.session)
  fastify.get('/api/auth/sessions', h.sessions)
  fastify.get('/api/auth/sessions/all', h.allSessions)
  fastify.get('/api/auth/sessions/:page', h.sessions)
  fastify.get('/api/auth/sessions/:page/:items', h.sessions)
  fastify.get('/api/user', h.read)
  fastify.get('/api/user/:user', h.read)
  fastify.get('/api/users', h.reads)
  fastify.get('/api/users/:page', h.reads)
  fastify.get('/api/users/:page/:items', h.reads)
  // fastify.put('/api/user', h.auth, h.update)
  // fastify.delete('/api/user', h.auth, h.delete)
  
  done()
}

module.exports = fp(plugin)