const crypto = require('crypto')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please enter your name!'],
    },
    email: {
      type: String,
      required: [true, 'A user must have an email'],
      unique: true,
      validate: [validator.isEmail, 'Please enter a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Please enter your password!'],
      minlength: 5,
      select: false,
    },

    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password!'],
      validate: {
        // This only works on create
        validator: function (el) {
          return el === this.password
        },
        message: 'Password are not the same!',
      },
    },
    phoneNumber: {
      type: String,
      unique: true,
      required: [true, 'Please enter a Phone number!'],
    },
    // paymentMethod: {
    //   type: mongoose.Schema.ObjectId,
    //   ref: 'PaymentMethod',
    //   // required: [true, 'You must choose a payment method!'],
    // },
    profileImage: {
      type: String, // URL to the user's profile picture
      default: 'https://abaygames.com/default2.jpg',
    },
    role: {
      type: String,
      enum: ['consumer', 'seller', 'admin'],
      default: 'consumer',
    },
    savedCars: {
      type: [mongoose.Schema.ObjectId],
      ref: 'Car',
    },
    postedCars: {
      type: [mongoose.Schema.ObjectId],
      ref: 'Car',
    },
    verified: {
      type: Boolean,
      default: false
    },
    verificationCode: {
      type: Number
    },
    passwordCreatedAt: Date,

    passwordUpdatedAt: Date,

    passwordResetToken: String,

    passwordResetExpires: Date,

    verificataionCodeExpires: Date,
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
    },
    toObj: {
      virtuals: true,
    },
  },
)
userSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'savedCars',
    select: '-__v',
  })
  this.populate({
    path: 'postedCars',
    select: '-__v',
  })
  next()
})
userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next()

  // Encrypt the password with cost(salt) of 12
  this.password = await bcrypt.hash(this.password, 12)
  // Delete passwordConfirm field
  this.passwordConfirm = undefined
  next()
})

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next()
  if(this.isModified('password')) {
    this.passwordUpdatedAt = Date.now() - 1000
  } else if(this.isNew) {
    this.passwordCreatedAt = Date.now() - 1000
  }
  next()
})

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword)
}

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10)
    return JWTTimestamp < changedTimestamp
  }
  return false
}

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex')

  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000

  return resetToken
}

userSchema.methods.changePassword = function () {
  this.passsword = crypto.createHash('sha256').update(resetToken).digest('hex')
  this.passwordChangedAt = Date.now() - 1000

  return resetToken
}

module.exports = mongoose.model('User', userSchema)
