import express from 'express'
import expressSession from 'express-session'
import connectRedis from 'connect-redis'
import Redis from 'ioredis'
import passportModule from 'passport'
import { Strategy as OAuth2Strategy } from 'passport-oauth2'

const passport = new passportModule.Passport()
passport.serializeUser((user, done) => {
  done(null, user)
})
passport.deserializeUser((user, done) => {
  done(null, user)
})
passport.use(
  'schedge',
  new OAuth2Strategy(
    {
      authorizationURL: 'http://localhost:3000/oauth/authorize',
      tokenURL: 'http://localhost:3000/oauth/token',
      clientID: '092ae554-0c26-4753-8e9b-0b7bb051a0d6',
      clientSecret: '77844689-b66e-49ae-be29-a4e30e05652f',
      callbackURL: 'http://localhost:4000/auth/callback',
      scope: 'profile reminders'
    },
    (accessToken, refreshToken, results, profile, callback) => {
      fetch('http://localhost:3000/api/me', {
        headers: {
          Authorization: `${results.token_type} ${accessToken}`
        }
      })
        .then(res => {
          if (!res.ok) throw new Error('Error fetching profile')
          return res.json()
        })
        .then(user => {
          callback(null, user)
        })
        .catch(callback)
    }
  )
)
// const redisClient = new Redis('redis://localhost:6379')

const RedisStore = connectRedis(expressSession)
const app = express()

app.use(
  expressSession({
    secret: 'everybodytothelimit',
    resave: false,
    saveUninitialized: false
    // store: new RedisStore({ client: redisClient })
  })
)
app.use(passport.session())
app.use(passport.initialize())

app.get(
  '/auth/callback',
  passport.authenticate('schedge'),
  (req, res, next) => {
    res.redirect('/')
  }
)
app.get('/login', passport.authenticate('schedge'))
app.use((req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
})

app.get('/', (req, res) => {
  console.log(req.user)
  res.send(`Hello ${req.user.username}`)
})

app.listen(4000)
