var passport = require('passport');
var util = require('./util');

var options = null;
var mailgun = null;

module.exports = {
  init: init,
  changePassword: changePassword,
  confirmEmail:confirmEmail,
  login: login,
  register: register,
  registerProvider: registerProvider,
  sendPasswordReset: sendPasswordReset,
  getResetUser: getResetUser,
  resetPassword: resetPassword,
  sendMailgun: sendMailgun,
  sendPasswordResetSimple: sendPasswordResetSimple
};

function confirmEmail($user, done) {

  var emailChange = $user.get('local.emailChange');
  if (!emailChange) return done('alreadyConfirmed');

  $user.set('email', emailChange.email, function(err) {
    if (err) return done(err);

    $user.set('local.email', emailChange.email, function(err) {
      if (err) return done(err);

      $user.del('local.emailChange', done);
    });

  });
}

function init(opts) {
  options = opts;
}

function sendMailgun(mailData, key, domain) {
  if (mailgun == null) {
    mailgun = require('mailgun-js')(key, domain);
  }
  return mailgun.messages.send(mailData, function(err, response, body) {
    return console.log(body);
  });
};

function changePassword(oldpassword, password, userId, model, done) {
  var $user = model.at(options.collection + '.' + userId);
  model.fetch($user, function(err) {
    if (err) return done(err);

    var user = $user.get();
    if (!user) {
      return done('You are not registered');
    }

    if (!user.local) {
      return done('You are not registered with password')
    }

    var oldpasswordHash = util.encryptPassword(oldpassword, user.local.salt);
    if (user.local.passwordHash !== oldpasswordHash) {
      return done({ oldpassword: 'Incorrect Old Password' });
    }

    var passwordHash = util.encryptPassword(password, user.local.salt);
    $user.set('local.passwordHash', passwordHash, function(err) {
      if (err) return done(err);

      return done();
    });
  });
}

function login(user, req, done) {
  req.session.userId = user.id;
  if (req.isAuthenticated()) {
    done(null, user);
  } else {
    req.login(user, function(err) {
      if (err) return done(err);

      done(null, user);
    });
  }
}

function registerProvider($user, provider, profile, req, res, done) {
  var userId = $user.leaf();

  var callback = function() {
//    if (options.passport.registerCallback) {
//      options.passport.registerCallback(req, res, $user.get(), function() {
//        login($user.get(), req, done);
//      });
//    } else {
//      login($user.get(), req, done);
//    }
//    if (err) return done(err);

    // Return $user
    done(null, $user);

  };
  var user = $user.get();

  if (user) {
    $user.set(provider, profile, function(err) {
      if (err) return done(err);
      $user.set('timestamps.registered', +new Date(), callback)
    })
  } else if (provider === 'linkedin') {
//    console.log('try to register through linkedIn');
    done(null, null, {});
  } else {
    var model = req.getModel();
    user = {
      id: userId || model.id(),
      timestamps: {
        registered: +new Date()
      }
    };
    user[provider] = profile;
    model.add(options.collection, user, function(err) {
      if (err) return done(err);

      $user = model.at(options.collection + '.' + user.id);

      callback();
    })
  }
}

function register(data, userId, model, req, res, done) {
  var email = data.email
      , password = data.password
      , firstname = data.firstname
      , lastname = data.lastname;
  email = email.toLowerCase();

  var query = { $limit: 1 };
  query['email'] = email;
  var $userQuery = model.query(options.collection, query);

  var $user = model.at(options.collection + '.' + userId);

  model.fetch($userQuery, $user, function(err) {
    if (err) return done(err);

    var user = $userQuery.get()[0];
    if (user) {
      return done({ email: 'User with this email already exists' });
    }

    if ($user.get('local')) {
      return done({ email: 'You are already registered' })
    }

    // Create local profile
    var salt = util.makeSalt();
    var profile = {
      emailChange: {
        email: email,
        timestamp: +new Date()
      },
      firstname: firstname,
      lastname: lastname,
      salt: salt,
      passwordHash: util.encryptPassword(password, salt)
    };

    var fullName = firstname + " " + lastname;

    if (!options.confirmRegistration) {
      options.sendmail && options.sendmail.manualRegistration(email, {
        username: email,
        password: password,
        name: fullName
      });
    } else {
      options.sendmail && options.sendmail.confirmRegistration(email, {
        username: email,
        password: password,
        name: fullName,
        userId: userId
      });
    }

    // Save user with profile
    registerProvider($user, 'local', profile, req, res, done);
  });
}

function sendPasswordReset(email, model, req, res, done) {
  email = email.toLowerCase();

  var $query = model.query(options.collection, {
    $limit: 1,
    'local.email': email
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    var user = $query.get()[0];
    if (!user) {
      return done({ email: 'There is no user with this email' });
    }

    var $user = model.at(options.collection + '.' + user.id),
        resetId = model.id();
    $user.set('local.pwResetId', resetId, function(err) {
      if (err) return done(err);

      var mailData = {
        from: "" + options.site.name + " <" + options.site.email + ">",
        to: email,
        subject: "Password Reset for " + options.site.name,
        text: "A new password for " + email + " can be changed via the form at " + resetId + (". Log in at " + options.site.domain),
        html: "A new password for <strong>" + email + "</strong> can be changed via the form at <strong>" + resetId + ("</strong>. Log in at " + options.site.domain)
      };

      var mailgunKey = options.mailgun.key;
      var mailgunDomain = options.mailgun.domain;
      if (mailgunKey !== null && mailgunKey !== "") {
        sendMailgun(mailData, mailgunKey, mailgunDomain);
      }
      done();
      //Maybe it makes sense to declare send function in options and pass it as follows:
      //options.resetPassword.email(email, resetId, done);
    });
  });
}

function getResetUser(resetId, model, done) {
  var $query = model.query(options.collection, {
    $limit: 1,
    'local.pwResetId': resetId
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    if ($query.get()) {
      return done(null, $query.get()[0]);
    } else {
      return done(null, undefined);
    }

    model.unfetch($query);
  });
}

function resetPassword(resetId, password, model, done) {
  var $query = model.query(options.collection, {
    $limit: 1,
    'local.pwResetId': resetId
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    if (!$query.get() || !$query.get()[0]) return done('Your password reset form has expired');

    var user = $query.get()[0],
        $user = model.at(options.collection + '.' + user.id);

    $user.del('local.pwResetId', function(err) {
      if (err) return done(err);

      var passwordHash = util.encryptPassword(password, user.local.salt);
      $user.set('local.passwordHash', passwordHash, done);
    });
  });
}

function sendPasswordResetSimple(email, model, done) {
  var salt = util.makeSalt();
  var newPassword = util.makeSalt(); // use a salt as the new password too (they'll change it later)
  var passwordHash = util.encryptPassword(newPassword, salt);
  var $query = model.query(options.collection, {
    $limit: 1,
    'local.email': email
  });

  model.fetch($query, function (err) {
    if (err) return done(err);

    var user = $query.get()[0];
    if (!user) {
      return done({ email: 'There is no user with this email' });
    }

    var $user = model.at(options.collection + '.' + user.id);

    $user.set('local.salt', salt);
    $user.set('local.passwordHash', passwordHash, function (err) {
      if (err) return done(err);

      options.sendmail.resetPassword(email, {
        username: email,
        newPassword: newPassword
      });
      done();
    });
  });

}

