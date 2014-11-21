var passport = require('passport');
var extend = require('extend');
var LocalStrategy = require('passport-local').Strategy;
var auth = require('./auth');
var util = require('./util');

module.exports = function(options) {
  var localOptions = extend(true, { passReqToCallback: true, usernameField: 'email' }, options.passport);

  // Local Strategy
  passport.use(new LocalStrategy(localOptions,
    function(req, email, password, done) {
      var model = req.getModel();
      var query = { $limit: 1 };
      query['email'] = email.toLowerCase();
      var $userQuery = model.query(options.collection, query);

      model.fetch($userQuery, function(err) {
        if (err) { return done(err); }

        var user = $userQuery.get()[0];

        if (!user) {
          return done(null, false, { email: 'Email is not registered' });
        }

        user.local = user.local || {};

        password = password.trim();

        var passwordHash = util.encryptPassword(password, user.local.salt || '');
        var targetHash = user.local.passwordHash || user.local.hashed_password;
        if (targetHash !== passwordHash) {
          return done(null, false, { password: 'Incorrect password' });
        }

        return done(null, user);
      });
    }
  ));

  // Strategies
  for (var name in options.strategies) {
    var strategyObj = options.strategies[name];
    var conf = extend(true, {passReqToCallback: true}, strategyObj.conf);

    passport.use(new strategyObj.strategy(conf, function(req, accessToken, refreshToken, profile, done) {
      var model = req.getModel();
      var query = { $limit: 1 };
//      console.log('profile', profile);
      query[profile.provider + '.email'] = profile.email;
      var $providerQuery = model.query(options.collection, query);

      var $user = model.at(options.collection + '.' + req.session.userId);

      model.fetch($providerQuery, $user, function(err) {
        if (err) return done(err);

        var user = $providerQuery.get()[0];

        if (user && user[profile.provider]) {
          if (!$user.get() || user.id === $user.get('id')){
            return auth.login(user, req, done);
          }

          var $providerUser = model.at(options.collection + '.' + user.id);

          $providerUser.set(profile.provider + 'Deleted', user[profile.provider], function(){
            $providerUser.del(profile.provider, function(){
              finish();
            });
          });
        } else {
          finish();
        }


        function finish(){
          profile.accessToken = accessToken;
          profile.refreshToken = refreshToken;

          auth.registerProvider($user, profile.provider, profile, req, null, function(err){
            var res = req.res;

            if (err) {
              res.redirect(options.passport.failureRedirect+"?err="+encodeURIComponent(err));
            } else {
              if (options.passport.registerCallback) {
//                console.log('find respond', req.res)
                options.passport.registerCallback(req, res, $user.get(), function() {
                  auth.login($user.get(), req, done);
                });
              } else {
                auth.login($user.get(), req, done);
              }
            }
          });
        }
      });
    }));
  }
}