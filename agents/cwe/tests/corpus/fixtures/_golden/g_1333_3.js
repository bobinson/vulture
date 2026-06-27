// CWE-1333: overlapping wildcard alternation.
const v = new RegExp("(.*)*foo");
module.exports = { v };
