/**
 * @param {import('express').RequestHandler} handler
 * @return {import('express').RequestHandler}
 */
export default function wrap (handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res, next)
    } catch (ex) {
      next(ex)
    }
  }
}
