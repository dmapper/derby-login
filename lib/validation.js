var validator = require('validator');

var passwordLength = 6;

module.exports = {
  any: any,
  validate: validate,
  validateField: validateField
}

function any(errors) {
  return errors && Object.keys(errors).length;
}

function validate(data) {
  var errors = {};
  for (var key in data) {
    var error = validateField(key, data[key]);
    if (error) errors[key] = error;
  }
  if (data.password && data.confirm && data.password !== data.confirm) {
    errors.confirm = 'Confirmation does not match password';
  }
  return errors;
}

function validateField(key, value) {
  switch (key) {
    case 'email':
      if (!value) {
        return 'Email is required';
      } else if (!validator.isEmail(value)) {
        return 'Invalid Email format';
      }
      break;
    case 'password':
      if (!value) {
        return 'Password is required';
      } else if (!validator.isLength(value, passwordLength)) {
        return 'Password length should be more than ' + passwordLength;
      }
      break;
    case 'oldpassword':
      if (!value) {
        return 'Old password is required';
      }
      break;
    case 'confirm':
      if (!value) {
        return 'Confirmation is required';
      }
      break;
    case 'firstname':
      if (!value) {
        return 'First name is required';
      }
      break;
    case 'lastname':
      if (!value) {
        return 'Last name is required';
      }
      break;
  }
}