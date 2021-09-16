const fp = require('fastify-plugin')
const plugin = async function (fastify, opts, done) {
  const apiBase = opts.auth.api_base || opts.app.api_base || ''
  const apiVersion = opts.auth.api_version || opts.app.api_version || 'v1'
  const api = `${apiBase}/${apiVersion}`

  if (typeof opts.app === 'object') opts.app.auth_bpp = api
  else opts.app = { auth_bpp: api }

  const h = require('./handler')(fastify, opts)

  // Auth
  fastify.post(`${api}/auth/register`, h.create)
  fastify.post(`${api}/auth/login`, h.login)
  fastify.get(`${api}/auth/email`, h.verifyEmailLink)
  fastify.delete(`${api}/auth/logout`, h.logout)
  fastify.delete(`${api}/auth/logout/all`, h.logouts)
  fastify.delete(`${api}/auth/logout/session/:id`, h.logoutSession)

  // Session
  fastify.get(`${api}/auth/session`, h.session)
  fastify.get(`${api}/auth/session/:id`, h.session)
  fastify.get(`${api}/auth/sessions`, h.sessions)
  fastify.get(`${api}/auth/sessions/all`, h.allSessions)
  fastify.get(`${api}/auth/sessions/:page`, h.sessions)
  fastify.get(`${api}/auth/sessions/:page/:items`, h.sessions)

  // User
  fastify.get(`${api}/user`, h.read)
  fastify.post(`${api}/user/check`, h.checkUser)
  fastify.get(`${api}/user/check/:user`, h.checkUser)
  fastify.get(`${api}/user/:user`, h.read)
  fastify.get(`${api}/users`, h.reads)
  fastify.get(`${api}/users/:page`, h.reads)
  fastify.get(`${api}/users/:page/:items`, h.reads)
  fastify.put(`${api}/user`, h.update)
  fastify.delete(`${api}/user`, h.delete)

  done()
}

module.exports = fp(plugin)
