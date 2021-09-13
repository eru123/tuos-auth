const subject = '[::appname::] Email Verification'
const text = '::appname:: email verification code: ::code::\n\nIf you did not request any verification code from ::appname:: please ignore this email.'
const html = '<html><h1>::appname:: email verification</h1><br /><h3>verification code: ::code::</h3><hr /><p>If you did not request any verification code from ::appname:: please ignore this email.</p></html>'
module.exports = {
  subject,
  text,
  html
}
