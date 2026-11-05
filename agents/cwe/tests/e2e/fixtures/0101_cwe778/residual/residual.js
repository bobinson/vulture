// R9 Node callback-style forwarding with names the rule does not know
function readConfig(path, cb) {
  fs.readFile(path, (e, buf) => {
    try {
      cb(null, JSON.parse(buf));
    } catch (err) { // EXPECT: clean residual: R9a cb(err)
      cb(err);
    }
  });
}
function load(path, done) {
  try {
    done(null, parse(path));
  } catch (err) { // EXPECT: clean residual: R9b done(err)
    done(err);
  }
}
function loadP(path) {
  return new Promise((resolve) => {
    try {
      resolve({ ok: true, value: parse(path) });
    } catch (err) { // EXPECT: finding known-gap (residual, still reported): R9c resolve({ok:false, err})
      resolve({ ok: false, err });
    }
  });
}
// R10 EventEmitter error event
class Feed extends EventEmitter {
  pump() {
    try {
      this.push(this.read());
    } catch (err) { // EXPECT: finding known-gap (residual, still reported): R10 this.emit('error', err)
      this.emit('error', err);
    }
  }
}
// R11 retry loop: keep last error, rethrow after the loop (token in name)
async function refreshTokenWithRetry() {
  let lastErr;
  for (let i = 0; i < 3; i++) {
    try {
      return await refreshToken();
    } catch (e) { // EXPECT: finding known-gap (residual, still reported): R11 retry lastErr=e, rethrown later, security name
      lastErr = e;
      await sleep(100 * i);
    }
  }
  throw lastErr;
}
