// Safe: no nesting, anchored literal class.
const validator = new RegExp("^[A-Za-z]{1,16}$");
module.exports = { validator };
