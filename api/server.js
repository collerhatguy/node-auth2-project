const express = require("express")
const helmet = require("helmet")
const cors = require("cors")

const authRouter = require("./auth/auth-router.js")
const usersRouter = require("./users/users-router.js")

const server = express()

server.use(helmet())
server.use(express.json())
server.use(cors())

server.use("/api/auth", authRouter)
server.use("/api/users", usersRouter)

server.use((err, req, res, next) => { // eslint-disable-line
  const { status, message, stack } = err
  res.status(status || 500).json({
    message,
    stack,
  })
})

module.exports = server
