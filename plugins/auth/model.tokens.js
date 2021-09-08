module.exports = function (fastify) {
  const mongoose = fastify.mongoose
  const TokensSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    user_id: String,
    ip: String,
    device: String,
    created_at: Number,
    updated_at: Number
  }, { timestamp: true })
  return mongoose.model('Tokens', TokensSchema)
}
