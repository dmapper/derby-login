var ajax = require('../ajax');
var validation = require('../../lib/validation');

module.exports = ResetSimple;
function ResetSimple() {};
ResetSimple.prototype.name = 'auth:reset-simple';
ResetSimple.prototype.view = __dirname;

ResetSimple.prototype.create = function(model) {
  model.set('disabled', true);

  model.on('change', 'email', function() {
    model.del('errors.email');
  });

  model.on('all', 'errors.*', function() {
    var disabled = !model.get('email') || validation.any(model.get('errors'));
    model.set('disabled', disabled);
  })
}

ResetSimple.prototype.blur = function(field) {
  var model = this.model;
  var error = validation.validateField(field, model.get(field));
  if (error) {
    model.set('errors.' + field, error);
  }
}

ResetSimple.prototype.submit = function() {
  var model = this.model;

  var data = {
    email: model.get('email')
  }
  var errors = validation.validate(data);
  if (validation.any(errors)) return model.set('errors', errors);

  ajax('/auth/resetsimple', data, model, function() {
    model.set('success', true);
  });
}
