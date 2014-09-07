var debug = require('debug')('auth:session');

module.exports = function(options) {

  return function(req, res, next) {
    var model = req.getModel();
    var userId = req.session.userId;
    if (!userId) userId = req.session.userId = model.id();
    model.set('_session.userId', userId);

    if (req.isAuthenticated()) {
      debug('authenticated');
      if (!req.session.loggedIn) req.session.loggedIn = true;
      $user = model.at(options.collection + '.' + userId);
      $publicUser = model.at(options.publicCollection + '.' + userId);
      model.fetch($user, $publicUser, function(err) {
        model.set('_session.loggedIn', true);
        model.ref('_session.user', $publicUser);
        $user.set('timestamps.loggedin', +new Date());
        model.unfetch($user, next);
      })
    } else {
      debug('not authenticated');
      if (req.session.loggedIn) delete req.session.loggedIn;
      if (options.redirect && req.path !== options.passport.failureRedirect && req.method === 'GET') {
        return res.redirect(options.passport.failureRedirect);
      }
      next();
    }
  }
}