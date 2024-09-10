const { promisify } = require('util')
const User = require('../models/userModel')
const catchAsync = require('../utils/catchAsync')
const jwt = require('jsonwebtoken')
const AppError = require('../utils/appError')
const sendEmail = require('./../utils/email')

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  })
}

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id)

  if (process.env.NODE_ENV === 'production') secure: true //https

  res.status(statusCode).json({
    status: 'success',
    token,
    user,
  })
}

exports.signup = catchAsync(async (req, res, next) => {
  if (req.body.verificationCode) {
    delete req.body.verificationCode
  }

  const newUser = await User.create(req.body)

})

exports.login = catchAsync(async (req, res, next) => {
  const { email, phoneNumber, password } = req.body

  // 1. Check if phone number and password exist
  if (!phoneNumber || !email) {
    res.status(400).json({
      status: 'Please provide phone number or email!',
    })
  } else if (!password) {
    res.status(400).json({
      status: 'Please provide password!',
    })
  }

  //2. Check if user exists && password is correct
  const user = await User.findOne({
    $or: [
      {email: email},
      {phoneNumber: phoneNumber}
    ]
  }).select('+password')

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email, phone number or password', 401))
  }

  //Check account verification
  if(!user.verified) {
    res.status(401).json({
      status: 'verify',
      message: 'Please verify your account!'
    })
  }

  if (process.env.NODE_ENV === 'production') secure: true //https
    
  createSendToken(user, 200, res)

})

exports.sendVerificationCode = catchAsync(async (req, res, next) => {
  const verificationCode = Math.floor(Math.random() * (99999 - 10000 + 1) ) + 10000
  const {email} = req.body
  const user = await User.findOne({email: email})

  user.verificationCode = await bcrypt.hash(verificationCode, 12) 
  await user.save({ validateBeforeSave: false })

  const message = `Your email verification code is ${verificationCode}. Enter the above code in your application and do not share it with anyone.`
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your verification code (valid for 10 minutes)',
      message,
    })

    res.status(200).json({
      status: 'success',
      message: 'Code sent to email!',
    })
  } catch (err) {
    user.verificationCode = Number
    user.verificationCodeExpires = Date
    await user.save({ validateBeforeSave: false })

    // return next(new AppError('There was an error while sending the email. Try again later'), 500)
    return next(err)
  }
  

})

exports.verifyAccount = catchAsync(async (req, res, next) => {

  const verificationCode = req.body.verificationCode
  const {email} = req.body
  const user = await User.findOne({email: email})

  if(user.verificationCodeExpires < Date.now()) {
    user.verificationCode = Number
    user.verificationCodeExpires = Date
    return next(new AppError('Verification code expired! Please try again.', 401))
  }

  if (!verificationCode) {
    return next(new AppError('Please provide the verfication code', 401))
  }

  if (!(await bcrypt.compare(verificationCode, user.verificationCode))) {
    return next(new AppError('The verification code is not correct!', 401))
  }

  user.verified = true
  user.verificationCode = Number
  user.verificationCodeExpires = Date
  createSendToken(user, 200, res)

})

exports.protect = catchAsync(async (req, res, next) => {
  // 1. Get token and check if it's there
  let token
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1]
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log-in to get access!', 401))
  }

  const decodedToken = jwt.decode(token)

  if (!decodedToken) {
    return next(new AppError('You are not logged in! Please login to get access!', 401))
  }

  if (decodedToken.exp < Date.now() / 1000) {
    return next(new AppError('Session expired! Please login again.', 401))
  }

  const currentTimestamp = Math.floor(Date.now() / 1000) // Get current timestamp in seconds
  if (decodedToken.expiresIn && decodedToken.expiresIn < currentTimestamp) {
    return next(new AppError('Session expired! Please login again.', 401))
  }

  // 2. Verify token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)

  // 3. Check if user still exists

  const currentUser = await User.findById(decoded.id)
  if (!currentUser) {
    return next(new AppError('The user belonging to this token no longer exists', 401))
  }
  if (currentUser.verify == false) {
    return next(new AppError('Please verify your account to continue!', 401))
  }

  // 4. Check if the user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please login again.', 401)) // 401 unauthorized
  }
  req.user = currentUser

  // Grant access to protected route

  next()
})

exports.restrictTo = (...roles) => {
  // passing values in middleware ...closure concept
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('you don`t have permission to perform this action', 403)) // 403 forbidden
    }
    next()
  }
}

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1.get user from posted email

  const user = await User.findOne({ 
    phoneNumber: req.body.phoneNumber
  })

  if (!user) {
    return next(new AppError('The user doesn`t exists', 401))
  }

  //2. generate the random reset token
  const resetToken = user.createPasswordResetToken()
  await user.save({ validateBeforeSave: false })

  //3. sennd to user's email
  const resetURL = `${req.protocol}://${req.get('host')}/api/v2/users/resetPassword/${resetToken}`

  // Also send short reset code to mobile phone

  const message = `Forgot your password? Submit an update request with your new password and confirm password to: ${resetURL}.\n If you didn't forget your password, please ignore this email!`
  const link = resetURL
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 minutes)',
      message,
      link,
    })

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    })
  } catch (err) {
    user.passwordResetToken = undefined
    user.passwordResetExpires = undefined
    await user.save({ validateBeforeSave: false })

    // return next(new AppError('There was an error while sending the email. Try again later'), 500)
    return next(err)
  }
})

exports.resetPassword = catchAsync(async (req, res, next) => {
  //1. Get user based on the token

  const user = await User.findOne({
    passwordResetToken: req.params.token,
    passwordResetExpires: { $gt: Date.now() },
  })

  //2.if token hasnot expired ,and there is user, set new password
  if (!user) {
    return next(new AppError('Token is invalid or expired', 400))
  }

  user.password = req.body.password
  user.passwordConfirm = req.body.passwordConfirm
  user.passwordResetToken = undefined
  user.passwordExpires = undefined
  await user.save()

  // 3. Update password changedAt property for the user

  // 4. Log the user in, send JWT
  createSendToken(user, 200, res)
})

exports.updatePassword = catchAsync(async (req, res, next) => {
  //1. get user from collection

  const user = await User.findById(req.user.id).select('+password')

  //2. check if posted current password is correct
  const correct = await user.correctPassword(req.body.oldPassword, user.password)
  if (!user || !correct) {
    return next(new AppError('your old password is wrong', 401))
  }

  //3. if correct ,update password

  user.password = req.body.password
  user.passwordConfirm = req.body.passwordConfirm
  await user.save()

  //4. send token
  createSendToken(user, 200, res)
})

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  })
  res.status(200).json({
    status: 'success',
  })
}
