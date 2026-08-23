function issueOneTimeCode(user) {
  const otp = Math.random().toString().slice(2, 8);
  store.put(user.id, otp);
  return otp;
}
