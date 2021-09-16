# tuos-auth
Tuos authentication plugin

### Installation
```bash
# npm
npm i tuos-mongoose tuos-auth

# yarn
yarn add tuos-mongoose tuos-auth
```

### Basic Usage
`tuos-auth` can be used as a `fastify-plugin`
```js
const options = {
  mongoose: { 
    // see more: https://github.com/eru123/tuos-mongoose
    connect: 'mongodb://localhost:27017/tuos' 
  },
  jwt: {
    secret_token: '<your_secret_token>'
  },
  auth: {
    // for email verification
    api_url: 'http://localhost:8080', // url where your api is hosted
    client_url: 'http://localhost:3000', // your web app url, this will be used as fallback url
    code_expiration: '1800000', // default

    // for templating emails
    mailer: {
      vars: [
        {
          name: 'appname', // variable name
          find: /::appname::/g, // string or regex
          default: 'Tuos' // fallback value if var Boolean(vars[n].name) is false
        },
        {
          name: 'codelink',
          find: /::codelink::/g
        },
        {
          name: 'username',
          find: /::username::/g
        }
      ],
      templates: {
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
    }
  },
  mailer: {
    // see https://nodemailer.com/
    transport: {
      secure: true,
      host: '<smtp_server>',
      port: 587,
      auth: {
        user: '<your_email>',
        pass: '<email_password>'
      }
    },
    defaults: {
      // sendMail defaults
    }
  }
}

// tuos-mongoose must be registered first before tuos-auth
fastify.register(require('tuos-mongoose'), options)
fastify.register(require('tuos-auth'), options)

/*
* Register your other plugins
* that depends on tuos-auth or
* tuos-mongoose
*/

fastify.listen(process.env.PORT, '0.0.0.0')
```

### Reference
 - [tuos-tera](https://github.com/eru123/tuos-tera)
 - [tuos-mongoose](https://github.com/eru123/tuos-mongoose)