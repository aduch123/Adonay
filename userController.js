const User = require('../models/userModel')
const catchAsync = require('../utils/catchAsync')
const AppError = require('../utils/appError')

exports.getMe = catchAsync(async (req, res, next) => {
  const userId = req.user.id

  const user = await User.findById(userId).select('-__v -password')

  res.status(200).json({
    status: 'success',
    user,
  })
})

exports.countDocuments = catchAsync(async (req, res, next) => {
  User.countDocuments(function (err, count) {
    res.status(200).json({
      status: 'success',
      result: count,
    })
    if (err) {
      return next(new AppError(err, 400))
    }
  })
  // If you want to count all documents in a large collection, use the estimatedDocumentCount()
  //  function instead. If you call countDocuments({}), MongoDB will always execute a full collection
  //   scan and not use any indexes.
})

exports.updateProfile = catchAsync(async (req, res, next) => {
  const userId = req.user.id

  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. Please use /updateMyPassword', 400))
  }

  const updatedUser = await User.findByIdAndUpdate(userId, req.body, {
    new: true,
    runValidators: true,
  })
  res.status(200).json({
    status: 'success',

    updatedUser,
  })
})

exports.deleteProfile = catchAsync(async (req, res, next) => {
  const userId = req.user.id

  const deletedUser = await User.findByIdAndUpdate(userId, {
    active: false,
  })

  res.status(204).json({
    status: 'success',
    users: null,
  })
})

// ======================Admin=========================
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const doc = await User.find().select('-__v -password -activationCode')
  if (!doc) {
    return next(new AppError('No users found', 404))
  }

  res.status(200).json({
    status: 'success',
    result: doc.length,
    doc,
  })
})

exports.getSingleUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id
  const user = await User.findById(userId)

  if (!user) {
    return next(new AppError('NO user found with that Id', 404))
  }

  res.status(200).json({
    status: 'success',

    user,
  })
})

exports.getUsers = catchAsync(async (req, res, next) => {
  const usersInfo = req.body
  const users = await User.find(usersInfo)

  if (!users) {
    return next(new AppError('NO users found with that info', 404))
  }

  res.status(200).json({
    status: 'success',
    users,
  })
})

exports.updateUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id

  const updatedUser = await User.findByIdAndUpdate(userId, req.body, {
    new: true,
    runValidators: true,
  })

  if (!updatedUser) {
    return next(new AppError('NO user found with that Id', 404))
  }

  res.status(200).json({
    status: 'success',

    updatedUser,
  })
})

exports.deleteUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id

  const deletedUser = await User.findByIdAndDelete(userId)

  if (!deletedUser) {
    return next(new AppError('NO user found with that Id', 404))
  }
  res.status(204).json({
    status: 'success',
    user: null,
  })
})

exports.updateUserActiveStatusByProvider = catchAsync(async (req, res, next) => {
  const userId = req.params.id
  const user = await User.findOne({
    _id: userId,
  })
  let changeStatus
  if (user.active == true) {
    changeStatus = false
  }
  if (user.active == false) {
    changeStatus = true
  }
  const updatedUser = await User.findByIdAndUpdate(
    userId,
    {
      active: changeStatus,
    },
    {
      new: true,
      runValidators: true,
    },
  )

  if (!updatedUser) {
    return next(new AppError('No user found with that Id', 404))
  }

  res.status(200).json({
    status: 'success',
    user: updatedUser,
  })
})
