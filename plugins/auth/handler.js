const _ = require('lodash')
const Joi = require('joi')
const Phone = Joi.extend(require('joi-phone-number'))
const bcrypt = require('bcrypt')
const passwordComplexity = require('joi-password-complexity')

const handler = function(fastify){
  const Users = fastify.mongoose.models.Users
  const Tokens = fastify.mongoose.models.Tokens

  // create a new token
  const newJWTToken = (payload) => String(fastify.jwt.sign({ ..._.pick(payload, (['_id', 'name', 'user', 'role'])) }))

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
    'phoneVerified',
    'email',
    'emailVerified',
    'created_at',
    'updated_at',
    'role'
  ]

  const readResponseSchema = [
    '_id',
    'name',
    'user',
    'created_at'
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

  // validate data for registration
  const validateUserRegistration = (user) => {
    const schema = Joi.object({
      name: Joi.string().min(3).max(255).required(),
      user: Joi.string().alphanum().min(3).max(30).required(),
      email: Joi.string().email().required(),
      pass: passwordComplexity(complexityOptions).required(),
      phone: Phone.string().phoneNumber(),
    })
    return schema.validate(user)
  }

  // validate data for update
  const validateUserUpdate = (user) => {
    const schema = Joi.object({
      name: Joi.string().min(3).max(255),
      user: Joi.string().alphanum().min(3).max(30),
      email: Joi.string().email().required(),
      pass: passwordComplexity(complexityOptions).required(),
      npass: passwordComplexity(complexityOptions),
      phone: Phone.string().phoneNumber(),
    })
    return schema.validate(user)
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

  // create user
  const create = async function(req, res){

    // filter request body
    const userdata = _.pick(req.body, ['name', 'user', 'email', 'phone','pass'])

    // validate the request
    const { error } = validateUserRegistration(req.body)
    if(error) return res.send({ type:'error', message: error.details[0].message })

    // check if username or email is already registered
    let user = await Users.findOne({ user: userdata.user })
      .catch(e =>  {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({type:'error',message: 'Username is already taken'})
      })
    if(res.sent) return
    if(user) return res.send({type:'error',message: 'Username is already taken'})

    // get current timestamp
    const tstamp = Date.now()

    const isFirst = await hasUser()
    // create user object from User model
    user = new Users(userdata)
    user.pass = await pash(user.pass)
    user.phoneVerified = false
    user.emailVerified = false
    user.role = isFirst ? 'user' : 'admin'
    user.created_at = tstamp
    user.updated_at = tstamp

    // save user to database
    return await user.save()
      .then((u) => createTokenRecord(req, u._doc))
      .then((t) => res.code(200).send({
        type: 'success',
        message: 'User created successfully',
        data: _.pick(user._doc, userResponseSchema),
        token: t._doc.token
      }))
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.code(200).send({
          type: 'error',
          message: 'Failed to register. Please contact your administrator to fix this error'
        })
      })
  }

  // login handler
  const login = async function(req, res){
    // filter request body
    const userdata = _.pick(req.body, ['user', 'pass'])

    // check if user exists
    const user = await Users.findOne({user: userdata.user})
      .catch(e =>  {
          console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
          return res.send({type:'error', message: 'Server Error: Failed while finding the user'})
      })
    if(res.sent) return
    if(!user) return res.send({type:'error',message: 'User does not exist'})

    // check if password is correct
    const valid = await bcrypt.compare(userdata.pass, user.pass)
    if(!valid) return res.send({type:'error',message: 'Invalid password'})

    // create token
    return await createTokenRecord(req, user._doc)
      .then((t) => // return response
        res.code(200).send({
          type: 'success',
          message: 'User logged in successfully',
          data: _.pick(user._doc, userResponseSchema),
          token: t._doc.token
        }))
      .catch((e) => {
          console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
          return res.code(200).send({
            type: 'error',
            message: 'Server Error: Failed to login',
          })
        })
  }

  // logout handler for logging out current session
  const logout = async (req, res) => {
    // check if token is valid
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

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
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

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
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})
    
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
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

    const record = await readTokenRecord(req)
    if (!record) return res.send({ type: 'error', message: 'Session not found' })
    return res.send({ type: 'success', message: 'Session found', data: { ..._.pick(record, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: record.token === req.token } })
  }

  // read many other token data
  const sessions = async (req, res) => {
    // check if token is valid
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

    const records = await readTokenRecords(req)
    if (!records) return res.send({ type: 'error', message: 'Sessions not found' })
    const result = []
    records.docs.forEach(r => result.push({ ..._.pick(r, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: r.token === req.token }))
    if (res.sent === false) return res.send({ type: 'success', message: `${result.length} sessions found`, size: result.length, data: result })
  }

  // read all token data
  const allSessions = async (req, res) => {
    // check if token is valid
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

    const records = await readAllTokenRecords(req)
    if (!records) return res.send({ type: 'error', message: 'Sessions not found' })
    const result = []
    records.forEach(r => result.push({ ..._.pick(r, ['_id', 'user_id', 'created_at', 'device', 'ip']), is_current: r.token === req.token }))
    return res.send({ type: 'success', message: `${result.length} sessions found`, size: result.length, data: result })
  }

  // read handler for getting user data
  const read = async (req, res) => {
    // check if token is valid
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

    // email regex
    const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

    // parse user request
    const id = req.params.user || req.user._id
    const find = id.match(/^[0-9a-fA-F]{24}$/) ? { _id: id } : id.match(emailRegex) ? { email: id } : { user: id }

    // get user data
    const user = await Users.findOne(find)
      .catch((e) => {
        console.log(`${Date.now()} [AUTH] ${e.name}: ${e.message}`)
        return res.send({ type: 'error', message: 'Server Error: Failed to get user data.' })
      })
    if(!user) return res.send({ type: 'error', message: 'User not found' })

    // reply
    console.log('admin >> ', req.user.role === 'admin')
    return res.send({ 
      type: 'success', 
      message: 'User found', 
      data: req.user.role === 'admin' || 
        user._doc._id === req.user._id ? 
        user._doc: _.pick(user._doc, readResponseSchema)
    })
  }

  // Reads Users Handler
  const reads = async (req, res) => {
    // check if token is valid
    if(!req.authenticated) return res.send({type:'error',message: 'Invalid token'})

    const pg = _.pick(req.params, ['page', 'items'])
    const page = pg.page || 1
    const items = pg.items || 20
    const users = await Users.paginate({}, { page: page, limit: items })
    const result = []
    users.docs.forEach(u => result.push(req.user.role === 'admin' || u._id === req.user._id ? u : _.pick(u, readResponseSchema)))
    res.send({
      status: 'success',
      message: `${users.docs.length} users found.`,
      size: result.length,
      data: result
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
    reads
  }
  
}

module.exports = handler