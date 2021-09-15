const fp = require('fastify-plugin')
const nodemailer = require('nodemailer')

const mailer = async (fastify, opts, next) => {
  const options = opts.mailer || (() => {
    throw new Error('options.mailer is not defined')
  })()

  const optsTranport = options.transport || (() => {
    throw new Error('options.mailer.transport is not defined')
  })()

  const optsDefaults = options.defaults || {}

  const namespace = options.namespace || 'mailer'

  const transporter = nodemailer
    .createTransport(optsTranport, optsDefaults)

  const send = async mailOptions => await transporter.sendMail(mailOptions)
  const verify = transporter.verify

  await verify()
    .then(() => console.log('[PLUGIN] mailer: connected'))

  fastify.decorate(namespace, {
    instance: nodemailer,
    send,
    verify,
    transporter
  })

  next()
}

module.exports = fp(mailer)
