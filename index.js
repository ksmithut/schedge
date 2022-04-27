import crypto from 'node:crypto'
import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import prismaClient from '@prisma/client'
import { z } from 'zod'
import wrap from './lib/wrap.js'
import { requireSessionUser } from './lib/auth.js'

const {
  PORT = '3000',
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GITHUB_REDIRECT_URI,
  COOKIE_SECRETS
} = process.env

const prisma = new prismaClient.PrismaClient()
const app = express()

app.set('view engine', 'pug')
app.set('views', new URL('./views/', import.meta.url).pathname)

app.use(cookieParser(COOKIE_SECRETS.trim().split(/\s+/)))
app.use(
  wrap(async (req, res, next) => {
    const sessionId = req.signedCookies.sid
    if (!sessionId) return next()
    const session = await prisma.session.findFirst({
      where: {
        id: sessionId,
        expiresAt: { gt: new Date() },
        revokedAt: null
      },
      include: { user: { include: { githubUser: true } } }
    })
    if (session) {
      res.locals.user = session.user
      res.locals.session = session
    }
    next()
  })
)

app.get(
  '/',
  requireSessionUser(),
  wrap(async (req, res) => {
    const reminders = await prisma.reminder.findMany({
      where: {
        userId: res.locals.user.id
      }
    })
    res.render('reminder/index', {
      reminders
    })
  })
)

app.get('/new', requireSessionUser(), (req, res) => {
  res.render('reminder/new')
})

const newReminderSchema = z.object({
  label: z.string().min(2),
  date: z.string().transform(date => {
    return z.date().parse(new Date(date))
  })
})

app.post(
  '/new',
  requireSessionUser(),
  express.urlencoded({ extended: true }),
  wrap(async (req, res) => {
    const result = newReminderSchema.safeParse(req.body)
    if (result.success) {
      await prisma.reminder.create({
        data: {
          id: crypto.randomUUID(),
          date: result.data.date,
          label: result.data.label,
          userId: res.locals.user.id
        }
      })
      return res.redirect('/')
    }
    const errors = result.error.issues.reduce((errors, issue) => {
      errors[issue.path.join('.')] = issue
      return errors
    }, {})
    console.log(errors)
    res.render('reminder/new', {
      errors
    })
  })
)

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' })
})

app.get(
  '/logout',
  wrap(async (req, res) => {
    if (res.locals.session) {
      await prisma.session.delete({
        where: { id: res.locals.session.id }
      })
    }
    res.clearCookie('sid')
    res.redirect('/')
  })
)

app.get('/login/github', (req, res) => {
  const state = crypto.randomUUID()
  const redirectURL = new URL('https://github.com/login/oauth/authorize')
  redirectURL.searchParams.set('client_id', GITHUB_CLIENT_ID)
  redirectURL.searchParams.set('redirect_uri', GITHUB_REDIRECT_URI)
  redirectURL.searchParams.set('scope', 'user')
  redirectURL.searchParams.set('state', state)
  res.cookie('github_oauth_state', state, {
    httpOnly: true,
    maxAge: 300 * 1000,
    sameSite: 'lax',
    signed: true
  })
  res.redirect(redirectURL.toString())
})

app.get('/login/github/callback', (req, res, next) => {
  const { code, state } = req.query
  const reqState = req.signedCookies.github_oauth_state
  res.clearCookie('github_oauth_state')
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
      return fetch('https://api.github.com/user', {
        headers: {
          Authorization: `token ${data.access_token}`
        }
      })
    })
    .then(response => response.json())
    .then(user => {
      return prisma.githubUser.upsert({
        where: {
          id: user.node_id
        },
        update: {
          login: user.login,
          avatarURL: user.avatar_url
        },
        create: {
          id: user.node_id,
          avatarURL: user.avatar_url,
          login: user.login,
          user: {
            create: {
              id: crypto.randomUUID(),
              username: user.login
            }
          }
        }
      })
    })
    .then(githubUser => {
      const now = new Date()
      const expiresAt = new Date(now)
      expiresAt.setDate(expiresAt.getDate() + 14)
      return prisma.session.create({
        data: {
          id: crypto.randomUUID(),
          userId: githubUser.userId,
          createdAt: now,
          expiresAt
        }
      })
    })
    .then(session => {
      res.cookie('sid', session.id, {
        httpOnly: true,
        expires: session.expiresAt,
        sameSite: 'lax',
        signed: true
      })
      res.redirect('/')
    })
    .catch(next)
})

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
