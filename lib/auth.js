export function requireSessionUser ({ redirectTo = '/login' } = {}) {
  return (req, res, next) => {
    if (res.locals.user) return next()
    res.redirect(redirectTo)
  }
}
