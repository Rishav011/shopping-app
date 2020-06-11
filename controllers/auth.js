const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/user');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const {validationResult} = require('express-validator/check');

const transporter = nodemailer.createTransport(sendgridTransport({
  auth:{
    api_key:'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'
  }
})); 

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput:{email:''}
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput:{email:''},
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if(!errors){
    
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput:{email:email }
    });
  }
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage:  'Invalid email or password.',
          oldInput:{email:email },
          validationErrors:[]
        });
        
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              req.flash('success', 'Login successful');
              res.redirect('/');
            });
          }
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage:  'Invalid email or password.',
            oldInput:{email:email },
            validationErrors:[]
          });
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  
  if(!errors.isEmpty()){
    console.log(errors.array().msg);
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg ,
      oldInput : {email:email},
      validationErrors: errors.array()
    });
  }
    bcrypt
      .hash(password, 12)
      .then(hashedPassword => {
        const user = new User({
          email: email,
          password: hashedPassword,
          cart: { items: [] }
        });
        return user.save();
      })
      .then(result => {
        res.redirect('/login');
        return transporter.sendMail({
          to:email,
          from:'kumarrishav011@gmail.com',
          subject:'Sign up successful!',
          html:'<h1> You signed up successfully!</h1>'
        });
        }).catch(err =>{
          console.log(err);
        });
   
}

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req,res,next) =>{
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset',{
    path: '/edit',
    pageTitle: 'Reset Password',
    errorMessage:message
  });
}

exports.postReset = (req,res,next)=>{
  const email = req.body.email;
  crypto.randomBytes(32,(err,buffer)=>{
    if(err){
      console.log(err);
      redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({email:email}).then(user=>{
      if(!user){
        req.flash('error','Email does not exist!');
        res.redirect('/reset');
      }
      user.resetToken =  token;
      user.resetTokenExpiration = Date.now() + 3600000;
     return user.save();
    }).then(result =>{
      res.redirect('/login');
      return transporter.sendMail({
        to:req.body.email,
        from:'kumarrishav011@gmail.com',
        subject:'Reset password',
        html:`
        <p> Request for password reset</p>
        <p>Click on this <a href="http://localhost:3000/new-password/${token}">link</a> to reset password!</p>
        <p>The link will be valid for 1 hour only!</p>
        `});
    }).catch(err=>{
      console.log(err);
    });
  });
}

exports.getNewPassword = (req,res,next)=>{
  const token = req.params.token;
  User.findOne({resetToken:token,resetToken:{$gt: Date.now()}}).then(user =>{
    let message = req.flash('error');
    if (message.length > 0) {
      message = message[0];
    } else {
      message = null;
    }
    res.render('auth/new-password',{
      path: '/new-password',
      pageTitle: 'Enter New Password',
      errorMessage:message,
      userId: user._id.toString(),
      passwordToken:token
    });
  })
  .catch(err=>{
    console.log(err);
  });
}

exports.postNewPassword = (req,res,next)=>{
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;
  User.findOne({resetToken:passwordToken,
    resetTokenExpiration:{$gt:Date.now()},
    _id:userId
  }).then(user =>{
    resetUser=user;
    return bcrypt.hash(newPassword,12);
  }).then(hashedPassword=>{
      
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
  }).then(result=>{
    res.redirect('/login');
  })
  .catch(err=> { 
    console.log(err);

    })

}
