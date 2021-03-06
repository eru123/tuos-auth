const _ = require('lodash')
const Joi = require('joi')
const Phone = Joi.extend(require('joi-phone-number'))
const bcrypt = require('bcrypt')
const passwordComplexity = require('joi-password-complexity')
const USID = require('usid')
const usid = new USID()
const handler = function (fastify, opts) {
  const Users = fastify.mongoose.models.Users
  const Tokens = fastify.mongoose.models.Tokens
  const options = opts.auth || (() => { console.log('[PLUGIN] auth: Using default auth options'); return {} })()
  const linkExpiration = Number(options.link_expiration) || 1800000
  const apiUrl = options.api_url
  const apiBase = opts.app.auth_bpp
  const clientUrl = options.client_url
  const app = { ...opts.app }
  const mailer = options.mailer || {}

  function sleep (ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  const findUser = (user) => {
    user = String(user)
    const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    const _idRegex = /^[0-9a-fA-F]{24}$/
    if (user.match(_idRegex)) return { _id: user }
    if (user.match(emailRegex)) return { email: user }
    return { user }
  }

  // parsing mail templates
  const parseTemplates = (add) => {
    const parseKeys = (prefix, obj) => {
      const r = {}
      for (const k in obj) r[`${prefix}${k}`] = obj[k]
      return r
    }

    const pk = {
      ...parseKeys('app', app),
      ...parseKeys('user', add.user),
      ...parseKeys('code', add.code)
    }

    const rtd = {
      email_verification: {
        subject: '::appname:: - Email verification',
        text: 'Hi there ::username::! here is your email verification link: ::codelink::\n\nIf you did not request any verification link from ::appname:: please ignore this email.',
        html: '<html><h1>::appname:: email verification</h1><h3>Hi there ::username::! here is your email verification link: <a href="::codelink::">Click here</a></h3><hr /><p>If you did not request any verification code from ::appname:: please ignore this email.</p></html>'
      },
      forgot_password: {
        subject: '::appname:: - Forgot password',
        text: 'Hi there ::username::! here is your reset password link: ::codelink::\n\nIf you did not request any reset password link from ::appname:: please ignore this email.',
        html: '<html><h1>::appname:: reset password link</h1><h3>Hi there ::username::! here is your reset password link: <a href="::codelink::">Click here</a></h3><hr /><p>If you did not request any reset password link from ::appname:: please ignore this email.</p></html>'
      }
    }

    const vars = mailer.vars || [
      {
        name: 'appname',
        find: /::appname::/g
      },
      {
        name: 'codelink',
        find: /::codelink::/g
      },
      {
        name: 'username',
        find: /::username::/g
      }
    ]

    const rt = mailer.templates || rtd

    const r = {}
    for (const k in rt) {
      r[k] = {}
      for (const kk in rt[k]) {
        let t = String(rt[k][kk])
        vars.forEach(v => {
          t = typeof pk[v.name] === 'string' ? t.replace(v.find, pk[v.name]) : v.default || ''
        })
        r[k][kk] = t
      }
    }

    return r
  }

  // create a new token
  const newJWTToken = (payload) => String(fastify.jwt.sign({ ..._.pick(payload, (['_id', 'name', 'user', 'role'])) }))

  // validate data for registration
  const validateUserRegistration = (user) => {
    const schema = Joi.object({
      name: Joi.string().min(3).max(255).required(),
      user: Joi.string().alphanum().min(3).max(30).required(),
      email: Joi.string().email().required(),
      pass: passwordComplexity(complexityOptions).required(),
      phone: Phone.string().phoneNumber()
    })
    return schema.validate(user)
  }

  // validate data for update
  const validateUserUpdate = (user) => {
    const schema = Joi.object({
      name: Joi.string().min(3).max(255),
      user: Joi.string().alphanum().min(3).max(30),
      email: Joi.string().email(),
      pass: passwordComplexity(complexityOptions),
      npass: passwordComplexity(complexityOptions),
      return_url: Joi.string().uri(),
      error_url: Joi.string().uri(),
      data: Joi.object(),
      phone: Phone.string().phoneNumber()
    })
    return schema.validate(user)
  }

  const validateAdditionalData = (data) => {
    if (typeof data !== 'object' || Array.isArray(data)) return 'Data field must an object'
    for (const k in data) {
      if (typeof k !== 'string' || typeof data[k] !== 'string') {
        return 'key in data[key] must be a string'
      }
    }

    // returns false if valid
    return false
  }

  const parseJoiError = error => {
    try {
      let result = ''
      error.details.forEach(({ message }) => {
        result += message + '. '
      })
      return String(result).trim()
    } catch (e) {
      return 'Invalid form'
    }
  }

  // hash the password
  async function pash (pass) {
    const salt = await bcrypt.genSalt(10)
    const hashed = await bcrypt.hash(pass, salt)
    return hashed
  }

  // check if mongodb has a registered user
  const hasUser = async () => {
    const user = await Users.find({}).limit(1)
    return !!user
  }

  // create verification email link
  const newEmailLink = (payload) => {
    const data = _.pick(payload, ['user', 'email', 'email_code'])
    data.return_url = payload.return_url || ''
    data.error_url = payload.error_url || ''
    const token = String(fastify.jwt.sign(data))
    return `${apiUrl + apiBase}/auth/email?token=${token}`
  }

  // send verification email
  const sendVerificationEmail = async (user, fallbackUrls = {}) => {
    const ts = Date.now()
    if (user.email_expire > ts) {
      return { type: 'error', message: `A link has been sent to your email, to resend the link try again after ${Math.ceil((user.email_expire - ts) / 1000 / 60)} mins` }
    }

    user.email_code = usid.uid()
    user.email_expire = ts + linkExpiration

    const link = newEmailLink({
      ..._.pick(user, ['user', 'email', 'email_code']),
      ...fallbackUrls
    })
    const mailOpts = parseTemplates({ user: _.pick(user, userResponseSchema), code: { link, expiration: user.email_expire } }).email_verification
    mailOpts.to = user.email
    const mailSent = await fastify.mailer.send(mailOpts)
      .then(() => {
        return { type: 'success', message: 'Verification email sent' }
      })
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return { type: 'error', message: 'Email verification failed, please try again.' }
      })

    if (mailSent.type === 'success') {
      return await user.save()
        .then(e => {
          if (e) return { type: 'success', message: 'A verification link has been sent to your email' }
          else throw new Error('Error saving user')
        })
        .catch(e => {
          console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
          return { type: 'error', message: 'Email verification failed, please try again.' }
        })
    }
    return mailSent
  }

  // for checking if user exists or not
  const checkUser = async (req, res) => {
    try {
      let find
      if (typeof req.params === 'object' && req.params.user) {
        find = findUser(req.params.user)
      } else if (typeof req.body === 'object' && req.body.user) {
        find = findUser(req.body.user)
      } else throw new Error('user parameter is missing')

      return await Users.findOne(find)
        .then(e => {
          if (e) return res.send({ type: 'success', message: 'User found' })
          return res.send({ type: 'error', message: 'User not found' })
        })
        .catch((e) => {
          console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
          res.send({ type: 'error', message: 'Server error: failed to find user' })
        })
    } catch (e) {
      console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
      res.send({ type: 'error', message: 'Invalid request' })
    }
  }

  // verify email link
  const verifyEmailLink = async (req, res) => {
    try {
      const token = req.query.token
      const payload = fastify.jwt.verify(token)
      const user = await Users.findOne(_.pick(payload, ['user', 'email', 'email_code'])).catch(() => false)

      const errFallback = (f = 0) => {
        if (payload.error_url) {
          return res.redirect(payload.error_url)
        } else if (f === 1) {
          return res.send('SERVER ERROR')
        } else if (clientUrl) {
          return res.redirect(clientUrl)
        } else {
          return res.send('INVALID TOKEN')
        }
      }

      if (!user) return errFallback()
      if (!user.email_verified || user.status === 'pending') {
        if (!user.email_verified) user.email_verified = true
        if (user.status === 'pending') user.status = 'active'

        user.email_code = ''
        user.email_expire = 0
        user.updated_at = Date.now()

        await user.save()
          .catch((e) => {
            console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
            return errFallback(1)
          })

        if (res.sent) return res.sent
      }

      if (user.code_expiration < Date.now()) return errFallback()

      if (payload.return_url) {
        return res.redirect(payload.return_url)
      } else if (clientUrl) {
        return res.redirect(clientUrl)
      } else {
        return res.send('OK')
      }
    } catch (e) {
      console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
      return res.send('INVALID LINK')
    }
  }

  const newForgotPasswordLink = (payload) => {
    const { pass, code, _id } = payload
    const fallb = _.pick(payload, ['error_url', 'return_url'])
    const token = String(fastify.jwt.sign({ pass, code, _id, ...fallb }))
    return `${apiUrl + apiBase}/auth/password?token=${token}`
  }

  const forgotPassword = async (req, res) => {
    const body = _.pick(req.body, ['user', 'pass'])
    const find = findUser(body.user)

    const { error } = validateUserUpdate({ pass: body.pass })
    if (error) return res.send({ type: 'error', message: error.details[0].message })

    const user = await Users.findOne(find)
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server error: failed to find user' })
      })

    if (res.sent) return res.sent
    if (!user) return res.send({ type: 'error', message: 'User not found' })

    user.cont = user.cont || {}

    if (typeof user.cont.forgot_password === 'object') {
      const ofp = Number(user.cont.forgot_password.expiration)
      const ts = Date.now()
      if (ofp > ts) return res.send({ type: 'error', message: `We already sent you an email, try again after ${Math.ceil((ofp - ts) / 1000 / 60)} mins to resend.` })
    }

    const code = usid.uid()
    const expiration = Date.now() + linkExpiration

    user.cont = {
      ...user.cont,
      forgot_password: { code, expiration }
    }

    const data = {
      _id: user._id,
      code,
      pass: body.pass
    }

    const fallbackUrls = _.pick(req.body, ['return_url', 'error_url'])
    const link = newForgotPasswordLink({
      ...data,
      ...fallbackUrls
    })

    const mailOpts = parseTemplates({ user: _.pick(user, userResponseSchema), code: { link, expiration } }).forgot_password
    mailOpts.to = user.email
    await fastify.mailer.send(mailOpts)
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to send email' })
      })
    if (res.sent) return res.sent

    return await user.save()
      .then(() => res.send({ type: 'success', message: 'Email sent' }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to save in database' })
      })
  }

  const verifyForgotPassword = async (req, res) => {
    try {
      const token = req.query.token
      const { _id, code, pass } = fastify.jwt.verify(token)
      const fallb = _.pick(req.body, ['return_url', 'error_url'])
      const errFallback = (f = 0) => {
        if (fallb.error_url) {
          return res.redirect(fallb.error_url)
        } else if (f === 1) {
          return res.send('SERVER ERROR')
        } else if (clientUrl) {
          return res.redirect(clientUrl)
        } else {
          return res.send('INVALID TOKEN')
        }
      }

      const user = await Users.findOne({ _id }).catch(() => false)

      if (!user) return errFallback()
      if (user.email_verified && user.status === 'active' && typeof user.cont.forgot_password === 'object') {
        if (user.cont.forgot_password.code === code && Number(user.cont.forgot_password.expiration) > Date.now()) {
          user.pass = await pash(pass)
          user.cont.forgot_password.code = ''
          user.cont.forgot_password.expiration = 0
          await user.save()
            .then(() => {
              if (fallb.return_url) {
                return res.redirect(fallb.return_url)
              } else if (clientUrl) {
                return res.redirect(clientUrl)
              } else {
                return res.send('OK')
              }
            })
            .catch((e) => {
              console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
              return errFallback(1)
            })
          if (res.sent) return res.sent
        } else {
          return errFallback()
        }
      } else return errFallback()
    } catch (e) {
      console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
      return res.send('INVALID LINK')
    }
  }

  // create current user token record
  const createTokenRecord = async (req, payload) => {
    const tstamp = Date.now()
    const token = newJWTToken(payload)
    const data = { token, user_id: payload._id, role: payload.role }
    data.device = req.headers['user-agent']
    data.ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
    data.created_at = tstamp
    data.updated_at = tstamp
    const record = new Tokens(data)
    return await record.save()
      .catch(async (e) => {
        if (e.code === 11000) {
          await sleep(1)
          return await createTokenRecord(req, payload)
        } else throw new Error(e)
      })
  }

  // delete current token record
  const deleteTokenRecord = async (req) => await Tokens.deleteOne({ user_id: req.user._id, token: req.token })

  // deletes all users token record except current user
  const deleteTokensRecord = async (req) => await Tokens.deleteMany({ user_id: req.user._id, token: { $ne: req.token } })

  // delete specific record by id or token
  const deleteTokenRecordByIdOrToken = async (req) => await Tokens.deleteOne({ user_id: req.user._id, _id: req.params.id })

  // read single current token record
  const readTokenRecord = async (req) => await Tokens.findOne({ user_id: req.user._id, ...(req.params.id ? { _id: req.params.id } : { token: req.token }) })

  // read many token records
  const readTokenRecords = async (req, page = 1, items = 10) => await Tokens.paginate({
    user_id: req.user._id
  }, {
    page: req.params.page || page,
    limit: req.params.items || items
  })

  // read all token records
  const readAllTokenRecords = async (req) => await Tokens.find({ user_id: req.user._id })

  const userResponseSchema = [
    '_id',
    'name',
    'user',
    'phone',
    'phone_verified',
    'email',
    'email_verified',
    'email_expire',
    'created_at',
    'updated_at',
    'role',
    'status',
    'data',
    '__v'
  ]

  const readResponseSchema = [
    '_id',
    'name',
    'user',
    'data',
    'created_at'
  ]

  const paginateMetaSchema = [
    'totalDocs',
    'limit',
    'totalPages',
    'page',
    'pagingCounter',
    'hasPrevPage',
    'hasNextPage',
    'prevPage',
    'nextPage'
  ]

  // Password Complexity for Password Validation
  const complexityOptions = {
    min: 5,
    max: 1024,
    lowerCase: 1,
    upperCase: 1,
    numeric: 1,
    symbol: 1,
    requirementCount: 4
  }

  // create user
  const create = async function (req, res) {
    // filter request body
    const userdata = _.pick(req.body, ['name', 'user', 'email', 'pass'])
    const addData = typeof req.body.data === 'object' ? req.body.data : {}
    const fallbackUrls = _.pick(req.body, ['return_url', 'client_url'])

    const addDataError = validateAdditionalData(addData)
    if (addDataError) return res.send({ type: 'error', message: addDataError })

    // validate the request
    const { error } = validateUserRegistration(userdata)
    if (error) return res.send({ type: 'error', message: parseJoiError(error) })

    // check if username or email is already registered
    let user = await Users.findOne({ $or: [{ user: userdata.user }, { email: userdata.email }] })
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Username or email is already taken' })
      })

    if (res.sent) return res.sent
    if (user) return res.send({ type: 'error', message: 'Username or email is already taken' })

    // get current timestamp
    const tstamp = Date.now()

    const isFirst = await hasUser()
    // create user object from User model
    user = new Users(userdata)
    user.pass = await pash(user.pass)
    user.email_verified = !!isFirst
    user.role = isFirst ? 'admin' : 'user'
    user.status = isFirst ? 'active' : 'pending'
    user.data = addData
    user.cont = {}
    user.created_at = tstamp
    user.updated_at = tstamp

    // save user to database
    return sendVerificationEmail(user, fallbackUrls)
      .then((e) => {
        if (e.type === 'error') return res.send(e)
        if (user._doc.role === 'admin') return createTokenRecord(req, user._doc)
        return false
      })
      .then((t) => {
        if (!t) return res.send({ type: 'success', message: 'User created successfully' })
        if (t.type === 'error') return res.send(t)

        return res.send({
          type: 'success',
          message: 'User created successfully',
          data: _.pick(user._doc, userResponseSchema),
          token: t._doc.token
        })
      })
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.code(200).send({
          type: 'error',
          message: 'Failed to register. Please contact your administrator to fix this error'
        })
      })
  }

  // login handler
  const login = async function (req, res) {
    // filter request body
    const userdata = _.pick(req.body, ['user', 'pass'])
    const fallbackUrls = _.pick(req.body, ['return_url', 'client_url'])
    // check if user exists
    const user = await Users.findOne({ user: userdata.user })
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed while finding the user' })
      })

    if (res.sent) return res.sent
    if (!user) return res.send({ type: 'error', message: 'Invalid credentials' })

    // check if password is correct
    const valid = await bcrypt.compare(userdata.pass, user.pass)
    if (!valid) return res.send({ type: 'error', message: 'Invalid credentials' })

    if (user.status === 'pending') {
      const tstamp = Date.now()
      const exp = Number(user.email_expire)

      if (exp < tstamp) {
        return res.send({ ...await sendVerificationEmail(user, fallbackUrls), ok: false })
      } else return res.send({ type: 'error', message: `Account is not yet verified. Please check your email. To resend email verification, try to login your account after ${Math.ceil((exp - tstamp) / 1000 / 60)} mins` })
    }

    // create token
    return await createTokenRecord(req, user._doc)
      .then((t) => // return response
        res.send({
          type: 'success',
          message: 'User logged in successfully',
          data: _.pick(user._doc, userResponseSchema),
          token: t._doc.token
        }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({
          type: 'error',
          message: 'Server Error: Failed to login'
        })
      })
  }

  // logout handler for logging out current session
  const logout = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // delete token
    return await deleteTokenRecord(req)
      .then(() => res.send({ type: 'success', message: 'You are now logged out.' }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to logout.' })
      })
  }

  // logouts handler for logging out all user sessions except current session
  const logouts = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // delete token
    return await deleteTokensRecord(req)
      .then(() => res.send({ type: 'success', message: 'All sessions are now logged out.' }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to logout on other devices' })
      })
  }

  // logout specific user session
  const logoutSession = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // delete token
    return await deleteTokenRecordByIdOrToken(req)
      .then(() => res.send({ type: 'success', message: 'Session is now logged out.' }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to logout.' })
      })
  }

  // read current token data
  const session = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    const record = await readTokenRecord(req)
    if (!record) return res.send({ type: 'error', message: 'Session not found' })
    return res.send({ type: 'success', message: 'Session found', data: { ..._.pick(record, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: record.token === req.token } })
  }

  // read many other token data
  const sessions = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    const records = await readTokenRecords(req)
    if (!records) return res.send({ type: 'error', message: 'Sessions not found' })
    const result = []
    records.docs.forEach(r => result.push({ ..._.pick(r, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: r.token === req.token }))
    if (res.sent === false) {
      return res.send({
        type: 'success',
        message: `${result.length} sessions found`,
        size: result.length,
        data: result,
        ..._.pick(records, paginateMetaSchema)
      })
    }
  }

  // read all token data
  const allSessions = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    const records = await readAllTokenRecords(req)
    if (!records) return res.send({ type: 'error', message: 'Sessions not found' })
    const result = []
    records.forEach(r => result.push({ ..._.pick(r, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: r.token === req.token }))
    return res.send({ type: 'success', message: `${result.length} sessions found`, size: result.length, data: result })
  }

  // read handler for getting user data
  const read = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // parse user request
    const id = req.params.id || req.user._id
    const find = findUser(id)

    // get user data
    const user = await Users.findOne(find)
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to get user data.' })
      })

    if (res.sent) return res.sent
    if (!user) return res.send({ type: 'error', message: 'User not found' })

    // reply
    if (user.status === 'active') {
      return res.send({
        type: 'success',
        message: 'User found',
        data: req.user.role === 'admin' || user._doc._id === req.user._id ? user._doc : _.pick(user._doc, readResponseSchema)
      })
    } else {
      return res.send({ type: 'error', message: 'User information is not available' })
    }
  }

  // Reads Users Handler
  const reads = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    const pg = _.pick(req.params, ['page', 'items'])
    const page = pg.page || 1
    const items = pg.items || 20
    const users = await Users.paginate({}, { page: page, limit: items })
    const result = []
    users.docs.forEach(u => { if (u.status === 'active') result.push(req.user.role === 'admin' || u._id === req.user._id ? u : _.pick(u, readResponseSchema)) })
    res.send({
      status: 'success',
      message: `${users.docs.length} users found.`,
      size: result.length,
      data: result,
      ..._.pick(users, paginateMetaSchema)
    })
  }

  // update handler for updating user data
  const update = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // filter request body
    const data = _.pick(req.body, ['name', 'user', 'email', 'phone', 'pass', 'npass', 'data', 'return_url', 'error_url'])

    // validate data
    const { error } = validateUserUpdate(data)
    if (error) {
      return res.send({ type: 'error', message: parseJoiError(error) })
    }

    // parse user request
    const id = req.params.user || req.user._id
    const find = findUser(id)

    // get user data
    const user = await Users.findOne(find)
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to get user data.' })
      })

    if (res.sent) return res.sent
    // check if user exists
    if (!user) return res.send({ type: 'error', message: 'User not found' })

    // check if user is admin or owner of the data
    if (req.user.role !== 'admin' && String(user._id) !== req.user._id) return res.send({ type: 'error', message: 'You are not allowed to update this user' })

    // for admin
    if (req.user.role === 'admin') {
      if (data.user && data.user !== user.user) {
        const isUserExists = await Users.findOne({ user: data.user }).catch(e => {
          console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
          return res.send({ type: 'error', message: 'Server Error: Failed to check if user exists.' })
        })
        if (res.sent) return res.sent
        if (isUserExists) return res.send({ type: 'error', message: 'User already exists' })
        user.user = data.user
      }

      if (data.email && data.email !== user.email) user.email = data.email
      user.email_verified = data.email_verified || user.email_verified

      user.name = data.name
      // if (data.phone && data.phone !== user.phone) user.phone = data.phone // not available
      // user.phone_verified = data.phone_verified || user.phone_verified // not available

      user.role = data.role || user.role
      user.status = data.status || user.status

      if (data.pass) user.pass = await pash(data.pass)

      user.updated_at = Date.now()
    } else if (user.status === 'active') {
      // change username
      if (data.user && data.user !== user.user) {
        const isUserExists = await Users.findOne({ user: data.user })
          .catch(e => {
            console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
            return res.send({ type: 'error', message: 'Server Error: Failed to check if user exists.' })
          })
        if (res.sent) return res.sent
        if (isUserExists) return res.send({ type: 'error', message: 'User already exists' })
        user.user = data.user
      }

      // change name
      user.name = data.name || user.name

      // change email
      if (data.email && data.email !== user.email) {
        if (Number(user.email_expire) > Date.now()) return res.send({ type: 'error', message: `You need to wait for ${Number(user.email_expire) / 1000 / 60} mins before changing recovery email` })
        const emailCode = usid.uid()
        const expiration = Date.now() + linkExpiration
        user.email = data.email
        user.email_verified = false
        user.email_code = emailCode
        user.email_expire = expiration
        const fallbackUrls = _.pick(data, ['return_url', 'error_url'])
        const link = newEmailLink({
          ..._.pick(user, ['user', 'email', 'email_code']),
          ...fallbackUrls
        })
        const mailOpts = parseTemplates({ user: _.pick(user, userResponseSchema), code: { link, expiration } }).email_verification
        mailOpts.to = user.email
        await fastify.mailer.send(mailOpts)
          .catch((e) => {
            console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
            return res.send({ type: 'error', message: 'Server Error: Failed to send email' })
          })
        if (res.sent) return res.sent
      }

      // change password
      if (data.pass && data.npass) {
        if (data.npass === data.pass) return res.send({ type: 'error', message: 'New password cannot be the same as old password' })
        const pass = await bcrypt.compare(user.pass, data.pass)
        if (!pass) return res.send({ type: 'error', message: 'Invalid password' })
        user.pass = await pash(data.npass)
      }

      user.updated_at = Date.now()
    } else {
      return res.send({ type: 'error', message: 'You are not allowed to update this user' })
    }

    const addDataError = validateAdditionalData(data.data)
    if (addDataError) return res.send({ type: 'error', message: addDataError })

    user.data = { ...user.data, ...data.data || {} }

    // update user data
    return await user.save()
      .then(e => {
        return res.send({ type: 'success', message: 'User updated successfully', data: req.user.role === 'admin' ? e._doc : _.pick(e._doc, userResponseSchema) })
      })
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to update user data.' })
      })
  }

  // delete user handler
  const remove = async (req, res) => {
    // check if token is valid
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })

    // get id
    const id = req.params.user || req.user._id
    const find = findUser(id)

    // find user
    const user = await Users.findOne(find)
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: User not found' })
      })
    if (res.sent) return res.sent
    if (!user) return res.send({ type: 'error', message: 'User not found' })

    // check if user is admin or owner of the data
    if (req.user.role !== 'admin' && String(user._id) !== req.user._id) return res.send({ type: 'error', message: 'You are not allowed to delete this user' })

    // delete user
    return await Users.deleteOne(find)
      .then(() => res.send({ type: 'success', message: 'User deleted successfully' }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to delete user data.' })
      })
      .then(async () => {
        await Tokens.deleteMany({ user_id: String(user._id) })
        if (!res.sent) return res.send({ type: 'success', message: 'User deleted successfully' })
      })
      .catch(e => console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`))
      .finally(() => res.sent)
  }

  const renewToken = async (req, res) => {
    if (!req.authenticated) return res.send({ type: 'error', message: 'Invalid token' })
    const find = findUser(req.user._id)
    const user = await Users.findOne(find)
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: User not found' })
      })
    return await createTokenRecord(req, user._doc)
      .then(e => res.send({ type: 'success', message: 'Token renewed successfully', token: e._doc.token }))
      .catch(e => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to renew token' })
      })
  }

  return {
    create,
    login,
    logout,
    logouts,
    logoutSession,
    session,
    sessions,
    allSessions,
    read,
    reads,
    update,
    delete: remove,
    verifyEmailLink,
    checkUser,
    forgotPassword,
    verifyForgotPassword,
    renewToken
  }
}

module.exports = handler
