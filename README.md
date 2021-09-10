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
    code_expiration: '<milliseconds>'
  },
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