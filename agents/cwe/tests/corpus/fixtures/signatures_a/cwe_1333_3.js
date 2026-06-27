// CWE-1333: overlapping wildcard alternation.
const validator = new RegExp("(.*)*foo");
module.exports = { validator };
