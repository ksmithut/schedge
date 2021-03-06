/**
 * @param {object} [params]
 * @param {string} [params.redirectTo]
 * @returns {import('express').RequestHandler}
 */
export function requireSessionUser ({ redirectTo = '/login' } = {}) {
  return (req, res, next) => {
    if (res.locals.user) return next()
    res.cookie('return_to', req.originalUrl, {
      httpOnly: true,
      maxAge: 300 * 1000,
      sameSite: 'lax',
      signed: true
    })
    res.redirect(redirectTo)
  }
}

/**
 * @param {object} [params]
 * @param {string[]} [params.scopes=[]]
 * @returns {import('express').RequestHandler}
 */
export function requireAPIUser ({ scopes = [] }) {
  return (req, res, next) => {
    if (res.locals.accessToken) return next()
    return res.status(401).json({ error: 'Unauthorized' })
  }
}
