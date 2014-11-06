var debug = require('debug')('auth:routes');
var passport = require('passport');
var auth = require('./auth');
var validation = require('./validation');

module.exports = function (options) {

  function parseError(err) {
    var data = {};
    if (!err) return { success: true, url: options.passport.successRedirect };
    else if (err instanceof Error) data.error = err.message;
    else if (typeof err === 'string') data.error = err;
    else if (err.message) data.error = err.message;
    else data = err;
    debug('error', data);
    return data;
  }

  return function(req, res, next) {
    var parts = req.path.slice(1).split('/');
    var method = parts[1];
    debug('routes', parts);
    if (parts[0] === 'auth') {
      switch (method) {

        case 'changepassword':
          var model = req.getModel();

          var data = {
            oldpassword: req.body.oldpassword,
            password: req.body.password,
            confirm: req.body.confirm
          }
          var errors = validation.validate(data);
          if (validation.any(errors)) return res.json(errors);

          auth.changePassword(data.oldpassword, data.password, req.session.userId, model, function(err) {
            res.json(parseError(err));
          });
          break;

        case 'login':
          // Get user with local strategy
          passport.authenticate('local', options.passport, function(err, user, info) {
            // Error
            if (err || info) return res.json(parseError(err || info));
            // Success and actually login
            auth.login(user, req, function(err) {
              return res.json(parseError(err));
            });
          })(req, res);
          break;

        case 'logout':
          req.logout();
          delete req.session.userId;
          return res.redirect(options.passport.failureRedirect);
          break;

        case 'register':
          var model = req.getModel();

          var data = {
            email: req.body.email,
            password: req.body.password,
            firstname: req.body.firstname,
            lastname: req.body.lastname,
            confirm: req.body.confirm
          }
          var errors = validation.validate(data);
          if (validation.any(errors)) return res.json(errors);

          auth.register(data, req.session.userId, model, req, res, function(err) {
            res.json(parseError(err));
          });
          break;

        case 'resetrequest':
          var model = req.getModel(),
              data = {email: req.body.email},
              errors = validation.validate(data);

          if (validation.any(errors)) return res.json(errors);

          auth.sendPasswordReset(data.email, model, req, res, function(err) {
            if (err) return res.json(parseError(err));
            res.json({success: true});
          });

          break;

        case 'reset':
          var model = req.getModel(),
              data = {
                resetId: req.body.resetId,
                password: req.body.password,
                confirm: req.body.confirm
              }
          errors = validation.validate(data);

          if (validation.any(errors)) return res.json(errors);

          auth.resetPassword(data.resetId, data.password, model, function(err) {
            if (err) return res.json(parseError(err));
            res.json({success: true});
          });

          break;

        case 'resetsimple':
          var model= req.getModel(),
              data = {email: req.body.email},
              errors = validation.validate(data);

          if (validation.any(errors)) return res.json(errors);

          auth.sendPasswordResetSimple(data.email, model, function(err) {
            if (err) return res.json(parseError(err));
            res.json({success: true});
          });

          break;

        default:
          var strategy = options.strategies[method];
          if (!strategy) {
            return next(new Error('Unknown auth strategy: ' + method));
          } else {
            var conf = strategy.conf || {};
            var oldUser = !!req.user;
            if (parts[2] === 'callback') {
              var opt = {
                failureRedirect: options.passport.failureRedirect,
                registerCallback: options.passport.registerCallback
              };

//              console.log('before callback');
              passport.authenticate(method, opt)(req, res, function(request, respond) {
//                console.log('after callback');

                if (arguments.length === 0) {
                  if (oldUser) {
                    return res.redirect(options.passport.profileRedirect || options.passport.successRedirect);
                  }
                  return res.redirect(options.passport.successRedirect);
                }

                if (request) {
                  res.redirect(options.passport.successRedirect);
                } else {
                  console.log('arguments:', arguments);
                  throw new Error(req);
                }
              });
            } else {
//              console.log('before', method, conf);
              passport.authenticate(method, conf)(req, res, function() {
//                console.log('after', arguments);
                if (strategy.strategy.prototype.lti) {

                  if (req.query.redirect) {
                    res.redirect(req.query.redirect);
                  } else {
                    res.redirect(options.passport.successRedirect);
                  }

                }
              });
            }
          }
      }

    } else {
      next();
    }
  }
}
