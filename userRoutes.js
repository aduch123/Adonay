const express = require('express')
const router = express.Router()
const authController = require('../controllers/authController')
const userController = require('../controllers/userController')
const providerAuthController = require('../controllers/providerAuthController')

router.get(
  '/countDocuments',
  authContoller.protect,
  authController.restrictTo('admin'),
  userController.countDocuments,
)

router.post('/signup',authController.signup,)
router.post('/login', authController.login)
router.get('/logout', authController.logout)
router.post('/sendVerificationCode', authController.sendVerificationCode)
router.post('/verifyAccount', authController.verifyAccount)
router.post('/forgotPassword', authController.forgotPassword)
router.patch('/resetPassword/:token', authController.resetPassword)

router.get(
  '/profile',
  authController.protect,
  userController.getMe,
)

router.patch('/updateMyPassword', authController.protect, authController.updatePassword)

router.patch(
  '/updateProfile',
  authController.protect,
  userController.updateProfile,
)

router.delete(
  '/deleteProfile',
  authController.protect,
  userController.deleteProfile,
)

router.get(
  '/',
  authController.protect,
  providerAuthController.restrictTo('admin'),
  userController.getAllUsers,
)

router.get(
  '/users',
  authController.protect,
  providerAuthController.restrictTo('seller', 'admin'),
  userController.getUsers,
)

router.get(
  '/:id',
  authController.protect,
  providerAuthController.restrictTo('consumer', 'admin'),
  userController.getSingleUser,
)

router.patch(
  '/:id',
  authController.protect,
  providerAuthController.restrictTo('admin'),
  userController.updateUser,
)

router.delete(
  '/:id',
  authController.protect,
  providerAuthController.restrictTo('admin'),
  userController.deleteUser,
)
module.exports = router
