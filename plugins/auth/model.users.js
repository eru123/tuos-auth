module.exports = function (fastify) {
  const mongoose = fastify.mongoose
  const usersSchema = new mongoose.Schema({
    user: { type: String, required: true, unique: true },
    name: String,
    pass: String,
    created_at: Number,
    updated_at: Number,
    email: String,
    email_verified: Boolean,
    email_code: String,
    email_expire: Number,
    role: String,
    status: String, // account status (active|banned|pending)
    data: Object, // for additional public data created by other plugins
    cont: Object // for additional private data created by other plugins
  }, { timestamp: true })
  return mongoose.model('Users', usersSchema)
}
