module.exports = function (fastify) {
  const mongoose = fastify.mongoose
  const usersSchema = new mongoose.Schema({
    user: { type: String, required: true, unique: true },
    name: String,
    pass: String,
    created_at: Number,
    updated_at: Number,
    phone: String,
    phoneVerified: Boolean,
    email: String,
    emailVerified: Boolean,
    role: String
  }, { timestamp: true })
  return mongoose.model('Users', usersSchema)
}