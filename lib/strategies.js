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
      var query = {
        email: email.toLowerCase(),
        $limit: 1
      };

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
    var linkedInError = "We could not find your account - You have to first register to create a new account and you can then associate your account with your linked-in account to login automatically with one click";
    var strategyObj = options.strategies[name];
    var conf = extend(true, {passReqToCallback: true}, strategyObj.conf);

    passport.use(new strategyObj.strategy(conf, function(req, accessToken, refreshToken, profile, done) {

      var res = req.res;
      var conf = options.strategies[profile.provider].conf;

      var model = req.getModel();
      var email = profile.email.toLowerCase();

      var query = {
        email: email,
        $limit: 1
      };

      var $providerQuery = model.query(options.collection, query);

      var $user = model.at(options.collection + '.' + req.session.userId);

      model.fetch($providerQuery, $user, function(err) {
        if (err) return done(err);

        var userFound = $providerQuery.get()[0];
        var userEntered = $user.get();
        var provider = profile.provider;

        var foundProviderId = userFound[provider] && userFound[provider].id;

        if (conf.canConnect){
          handleConnectableProfile()
        } else {
          handleUsualProfile();
        }

        // Linked In
        function handleConnectableProfile(){
          console.log('handleConnectableProfile');
          // Не вошли - долбимся со страницы логина
          if (!$user.get()) {
            // Если нужный профиль не найден - редиректим с ошибкой
            if (!userFound || foundProviderId !== profile.id){
              var url = options.passport.failureRedirect+"?err="+encodeURIComponent(linkedInError)
              return res.redirect(url);
            // Если найден - логинемся в найденного
            } else {
              return auth.login(userFound, req, done);
            }
          }

          // Пытаемся подконектить профиль к уже существующему

          // Не найден юзер с таким email-ом или в нем нет провайдера
          // - добавляем провайдера
          if (!userFound || foundProviderId !== profile.id) return finish();

          // нашли юзера и он тот же самый под которым мы вошли
          // повторяем вход
          if (userFound.id === userEntered.id) return auth.login(userEntered, req, done);

          // Юзер под которым мы вошли отличается от найденного
          // И в найденном есть наш provider
          //
          // Удаляем из найденного провайдер, добавляем провайдер в профиль
          // под которым мы зашли
          delProviderFromUser(userFound.id, provider, function(err){
            finish();
          })
        }

        // Regular profile
        function handleUsualProfile() {
          // Не нашли
          if (!userFound) {
            // очищаем юзера - и создаем нового с нашим провайдером
            $user = model.at(options.collection + '.' + model.id());
            return finish();
          }

          // Нашли

          $user = model.at(options.collection + '.' + userFound.id);

          // В найденом юзере нет нужного профиля,
          // добавляем
          if (foundProviderId !== profile.id) return finish();

          // логинимся в найденного
          auth.login(userFound, req, done);
        }

        function delProviderFromUser(userId, provider, cb){
          var $user = model.at(options.collection + '.' + userId);
          var user = $user.getDeepCopy();

          user[provider + 'Deleted'] = user[provider];

          delete user[provider];

          $user.setDiffDeep(user, cb);
        }

        function finish(){
          profile.accessToken = accessToken;
          profile.refreshToken = refreshToken;

          profile.profkey = req.query.profkey;
          profile.profId = req.query.profId;
          profile.termId = req.query.termId;

//          console.trace('profile', profile);

          auth.registerProvider($user, profile.provider, profile, req, null, function(err){

            if (options.passport.registerCallback) {
              options.passport.registerCallback(req, res, $user.get(), function() {
                auth.login($user.get(), req, done);
              });
            } else {
              auth.login($user.get(), req, done);
            }

          });
        }
      });
    }));
  }
}