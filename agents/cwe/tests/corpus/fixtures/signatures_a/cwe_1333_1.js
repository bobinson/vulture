// CWE-1333: nested unbounded quantifier (catastrophic backtracking).
const re = /(a+)+$/;
module.exports = { re };
