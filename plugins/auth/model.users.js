module.exports = function (fastify) {
  const mongoose = fastify.mongoose
  const usersSchema = new mongoose.Schema({
    user: { type: String, required: true, unique: true },
    name: String,
    pass: String,
    created_at: Number,
    updated_at: Number,
    // phone: String, // not available yet
    // phoneVerified: Boolean,
    email: String,
    email_verified: Boolean,
    email_code: String,
    email_expire: Number,
    role: String,
    status: String, // account status (active|banned)
    data: { String: String } // for additional data created by other plugins
  }, { timestamp: true })
  return mongoose.model('Users', usersSchema)
}
