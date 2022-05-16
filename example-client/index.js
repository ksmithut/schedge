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
      clientID: 'fad3b373-7e5f-41f8-b8cb-fd294e257361',
      clientSecret: 'c0910e96-fee0-45bd-843f-69fdf9a57120',
      callbackURL: 'http://localhost:4000/auth/callback',
      scope: 'profile reminders'
    },
    (accessToken, refreshToken, results, profile, callback) => {
      console.log({ accessToken, refreshToken, results, profile, callback })
      callback(null, results)
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

app.get('/auth/callback', passport.authenticate('schedge'))
app.get('/login', passport.authenticate('schedge'))
app.use((req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
})

app.get('/', (req, res) => {
  console.log(req.user)
  res.send('Hello World')
})

app.listen(4000)
