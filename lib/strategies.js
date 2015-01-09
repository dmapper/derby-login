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

      var conf = options.strategies[profile.provider].conf;

      var model = req.getModel();
      var query = { $limit: 1 };
      query.email = profile.email;
      var $providerQuery = model.query(options.collection, query);

      var $user = model.at(options.collection + '.' + req.session.userId);

      model.fetch($providerQuery, $user, function(err) {
        if (err) return done(err);

        // нашли юзера с таким же email-ом в учетке провайдера
        var user = $providerQuery.get()[0];

        // юзер такой найден и в нем уже есть такой провайдер
        if (user && user[profile.provider]) {
          // Если мы не залогинены или залогинены в найденого юзера
          // просто делаем логин в найденого юзера и все
          if (!$user.get() || user.id === $user.get('id') || !conf.canConnect) {
            return auth.login(user, req, done);
          }

          // если залогинены, но юзер с найденым провайдером отличается от
          // залогиненого - в старом юзере переименовываем провайдера

          var $providerUser = model.at(options.collection + '.' + user.id);

          $providerUser.set(profile.provider + 'Deleted', user[profile.provider], function () {
            $providerUser.del(profile.provider, function () {
              finish();
            });
          });

        // Юзер с таким же email-ом найден, но правайдера в нем такого нет
        } else if (user && !user[profile.provider]) {
          // Если не linkedIn тогда будем вписывать ногого провайдера
          // в учетку с таким же email-ом, а не в ту которой мы щас
          // залогинены (одновременно перелогинемся)
          if (!conf.canConnect) {
            $user = model.scope(options.collection + '.' + user.id);
          }
          finish();

        // юзер с таким email-ом не найден
        // создаем / либо добавляем провайдера в
        // залогиненый профиль
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