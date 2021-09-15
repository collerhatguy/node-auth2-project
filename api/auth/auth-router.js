const router = require("express").Router()
const { checkUsernameExists, validateRoleName } = require('./auth-middleware')  
const { add } = require("../users/users-model")
const tokenBuilder = require("../auth/token-builder")
const bcrypt = require("bcryptjs")

router.post("/register", validateRoleName, (req, res, next) => {
  const { body, role_name } = req
  const { username, password } = body
  const hash = bcrypt.hashSync(password, 8)

  add({
    username,
    role_name,
    password: hash
  }).then(account => 
    res.status(201).json(account)
  ).catch(next)
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
  */
})

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { account, body } = req
  const { password, username } = body
  if (bcrypt.compareSync(password, account.password)) {
    const token = tokenBuilder(account)
    res.status(200).json({
      message: `${username} is back !`,
      token
    })
  } else {
    next({ 
      status: 401, 
      message: "invalid credentials" 
    })
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
  */
})

module.exports = router
