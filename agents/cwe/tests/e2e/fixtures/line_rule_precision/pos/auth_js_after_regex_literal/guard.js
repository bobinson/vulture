function trim(p) {
  return p.replace(/\/*$/, "");
}

function stamp(name) {
  return name.split(/`/).join("");
}

function guard(user) {
  if (!user.ok) {
    return access_denied(); // EXPECT: finding
  }
  return null;
}

module.exports = { trim, stamp, guard };
