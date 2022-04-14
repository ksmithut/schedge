import 'dotenv/config'
import express from 'express'

const { PORT = '3000' } = process.env

const app = express()

app.set('view engine', 'pug')
app.set('views', new URL('./views/', import.meta.url).pathname)

app.get('/', (req, res) => {
  res.render('index', { title: 'Home' })
})

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' })
})

app.get('/login/github', (req, res) => {
  res.status(501).send('Not Implemented')
})

app.get('/login/github/callback', (req, res) => {
  res.status(501).send('Not Implemented')
})

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
