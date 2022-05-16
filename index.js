import crypto from 'node:crypto'
import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import prismaClient from '@prisma/client'
import argon2 from 'argon2'
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
    res.render('index')
  })
)

app.get(
  '/reminders',
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

const newReminderSchema = z.object({
  label: z.string().min(2),
  date: z
    .string()
    .refine(val => !Number.isNaN(new Date(val).getTime()))
    .transform(date => z.date().parse(new Date(date)))
})

app
  .route('/reminders/new')
  .get(requireSessionUser(), (req, res) => {
    res.render('reminder/new')
  })
  .post(
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
        return res.redirect('/reminders')
      }
      const errors = result.error.issues.reduce((errors, issue) => {
        errors[issue.path.join('.')] = issue
        return errors
      }, {})
      res.render('reminder/new', {
        errors
      })
    })
  )

app.get(
  '/clients',
  requireSessionUser(),
  wrap(async (req, res) => {
    const clients = await prisma.clientApplication.findMany({
      where: {
        ownerId: res.locals.user.id
      }
    })
    res.render('client/index', { clients })
  })
)

const newClientSchema = z.object({
  name: z.string().min(2),
  redirectURIs: z
    .string()
    .refine(redirectURIs => {
      try {
        const uris = redirectURIs
          .trim()
          .split('\n')
          .map(line => line.trim())
          .filter(Boolean)
          .map(line => new URL(line.trim()))
        if (uris.length < 1) return false
        return true
      } catch {
        return false
      }
    }, 'Must be at least one redirect uri')
    .transform(redirectURIs => {
      return z.array(z.string().url()).parse(
        redirectURIs
          .trim()
          .split('\n')
          .map(line => line.trim())
          .filter(Boolean)
      )
    })
})

app
  .route('/clients/new')
  .get(
    requireSessionUser(),
    wrap(async (req, res) => {
      res.render('client/new', { data: {} })
    })
  )
  .post(
    requireSessionUser(),
    express.urlencoded({ extended: true }),
    wrap(async (req, res) => {
      const result = newClientSchema.safeParse(req.body)
      if (result.success) {
        const secret = crypto.randomUUID()
        const secretHash = await argon2.hash(secret)
        const client = await prisma.clientApplication.create({
          data: {
            id: crypto.randomUUID(),
            name: result.data.name,
            redirectURIs: JSON.stringify(result.data.redirectURIs),
            secretHash,
            ownerId: res.locals.user.id
          }
        })
        return res.render('client/show', { client, secret })
      }
      const errors = result.error.issues.reduce((errors, issue) => {
        errors[issue.path.join('.')] = issue
        return errors
      }, {})
      res.render('client/new', {
        errors,
        data: req.body
      })
    })
  )

app.get(
  '/clients/:id',
  requireSessionUser(),
  wrap(async (req, res) => {
    const client = await prisma.clientApplication.findFirst({
      where: {
        id: req.params.id,
        ownerId: res.locals.user.id
      }
    })
    if (!client) return res.render('404')
    res.render('client/show', { client })
  })
)

app.get(
  '/oauth/authorize',
  requireSessionUser(),
  wrap(async (req, res) => {
    res.json(req.query)
  })
)

app.post(
  '/oauth/token',
  express.json(),
  express.urlencoded({ extended: false }),
  wrap(async (req, res) => {
    res.json(req.body)
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

app.get(
  '/login/github/callback',
  wrap(async (req, res, next) => {
    const { code, state } = req.query
    const reqState = req.signedCookies.github_oauth_state
    res.clearCookie('github_oauth_state')
    if (state !== reqState) return res.redirect('/login')
    const accessTokenURL = new URL(
      'https://github.com/login/oauth/access_token'
    )
    accessTokenURL.searchParams.set('client_id', GITHUB_CLIENT_ID)
    accessTokenURL.searchParams.set('client_secret', GITHUB_CLIENT_SECRET)
    accessTokenURL.searchParams.set('code', code)
    accessTokenURL.searchParams.set('redirect_uri', GITHUB_REDIRECT_URI)
    const tokenResponse = await fetch(accessTokenURL.toString(), {
      method: 'POST',
      headers: { Accept: 'application/json' }
    })
    if (!tokenResponse.ok) throw new Error('Error getting token from github')
    const tokenResponseBody = await tokenResponse.json()
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `token ${tokenResponseBody.access_token}` }
    })
    if (!userResponse.ok) throw new Error('Error fetching user from github')
    const user = await userResponse.json()
    const githubUser = await prisma.githubUser.upsert({
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
    const now = new Date()
    const expiresAt = new Date(now)
    expiresAt.setDate(expiresAt.getDate() + 14)
    const session = await prisma.session.create({
      data: {
        id: crypto.randomUUID(),
        userId: githubUser.userId,
        createdAt: now,
        expiresAt
      }
    })
    res.cookie('sid', session.id, {
      httpOnly: true,
      expires: session.expiresAt,
      sameSite: 'lax',
      signed: true
    })
    res.clearCookie('return_to')
    const returnTo = req.signedCookies.return_to ?? '/'
    res.redirect(returnTo)
  })
)

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
