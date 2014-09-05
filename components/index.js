module.exports = function(app, options) {
  app.component(require('./changePassword'));
  app.component(require('./login'));
  app.component(require('./register'));
  app.component(require('./resetPassword'));
  app.component(require('./resetPasswordRequest'));
  app.component(require('./resetPasswordSimple'));
};
