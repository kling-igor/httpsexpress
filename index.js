const http = require('http')
const https = require('https')
const express = require('express')
const fs = require('fs')
const path = require('path')

const forceSSL = require('express-force-ssl')
const helmet = require('helmet')


const SSL_PORT = 8443

function isSecure(req) {
  // Check the trivial case first.
  if (req.secure) {
    return true
  }
  // Check if we are behind Application Request Routing (ARR).
  // This is typical for Azure.
  if (req.headers['x-arr-log-id']) {
    return typeof req.headers['x-arr-ssl'] === 'string';
  }
  // Check for forwarded protocol header.
  // This is typical for AWS.
  return req.headers['x-forwarded-proto'] === 'https';
}

function redirect(req, res, next) {
  if (isSecure(req)) {
    return next()
  }

  const host = req.headers['host'].replace(/:\d+$/, ":" + SSL_PORT)
  const redirectURL = "https://" + host + req.url
  res.redirect(redirectURL)
}

function cors(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")

  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET')
    return res.status(200)
  }
  next()
}

const app = express()

app.use(helmet())
app.set('forceSSLOptions', {
  httpsPort: SSL_PORT
})
app.use(forceSSL)

app.use(cors)

app.use(redirect)

app.use('/', function (req, res) {
  res.status(200).type('text/plain').send('Hello world!')
})

app.use((req, res, next) => {
  res.status(404).type('text/plain').send("Not found")
})

app.use((err, req, res, next) => {
  res.status(500).type('text/plain').send("Oops... Internal server error")
})

http.createServer(app).listen(8000)

const options = {
  key: fs.readFileSync(path.resolve(__dirname, 'localhost.key')),
  cert: fs.readFileSync(path.resolve(__dirname, 'localhost.cert')),
  // ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384',
  // honorCipherOrder: true,
  // secureProtocol: 'TLSv1_2_method',
  // requestCert: false,
  // rejectUnauthorized: false
}

https.createServer(options, app).listen(SSL_PORT)
