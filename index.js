import crypto from 'node:crypto'
import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import { fetch } from 'undici'

const {
  PORT = '3000',
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GITHUB_REDIRECT_URI,
  COOKIE_SECRETS
} = process.env

const app = express()

app.set('view engine', 'pug')
app.set('views', new URL('./views/', import.meta.url).pathname)

app.use(cookieParser(COOKIE_SECRETS.trim().split(/\s+/)))

app.get('/', (req, res) => {
  res.render('index', { title: 'Home' })
})

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' })
})

app.get('/login/github', (req, res) => {
  const state = crypto.randomUUID()
  const redirectURL = new URL('https://github.com/login/oauth/authorize')
  redirectURL.searchParams.set('client_id', GITHUB_CLIENT_ID)
  redirectURL.searchParams.set('redirect_uri', GITHUB_REDIRECT_URI)
  redirectURL.searchParams.set('scope', 'user')
  redirectURL.searchParams.set('state', state)
  res.cookie('github_oauth_state', state, {
    httpOnly: true,
    maxAge: 300,
    sameSite: 'strict',
    signed: true
  })
  res.redirect(redirectURL.toString())
})

app.get('/login/github/callback', (req, res, next) => {
  const { code, state } = req.query
  const reqState = req.signedCookies.github_oauth_state
  if (state !== reqState) return res.redirect('/login')
  const accessTokenURL = new URL('https://github.com/login/oauth/access_token')
  accessTokenURL.searchParams.set('client_id', GITHUB_CLIENT_ID)
  accessTokenURL.searchParams.set('client_secret', GITHUB_CLIENT_SECRET)
  accessTokenURL.searchParams.set('code', code)
  accessTokenURL.searchParams.set('redirect_uri', GITHUB_REDIRECT_URI)
  fetch(accessTokenURL.toString(), {
    method: 'POST',
    headers: {
      Accept: 'application/json'
    }
  })
    .then(response => response.json())
    .then(data => {
      res.json(data)
    })
    .catch(next)
})

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
