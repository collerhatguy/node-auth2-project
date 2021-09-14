const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const { findBy } = require("../users/users-model")

const restricted = (req, res, next) => {
  const token = req.header.authorization
  !token && next({ status: 401, message: "Token required" })
  jwt.verify(
    token,
    JWT_SECRET,
    (err, decoded) => {
      err && next({ status: 401, message: "token decoding failed" })
      req.decodedJWT = decoded
    }
  )  
  next()
}

const only = role_name => (req, res, next) => {
  const { role } = req.decodedJWT
  role_name === role && next()
  next({ 
    status: 403, 
    message: "This is not for you" 
  })
}


const checkUsernameExists = (req, res, next) => {
  const { username } = req.body
  findBy({ username }).then(([account]) => {
    if (account) {
      req.account === account
      next()
    }
    next({ 
      status: 401, 
      message: "Invalid credentials" 
    })
  }).catch(next)
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body
  if (role_name && role_name.trim()) {
    const trimmedRole = role_name.trim()
    trimmedRole === "admin" && next({ 
      status: 422,
      message: "Role name can not be admin" 
    })
    trimmedRole.length > 32 && next({ 
      status: 422,
      message: "Role name can not be longer than 32 chars"
    })
    req.body.role_name = trimmedRole
    next()
  }
  req.body.role_name = "student"
  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
