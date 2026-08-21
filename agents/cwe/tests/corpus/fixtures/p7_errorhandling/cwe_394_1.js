export async function loadProfile(base) {
  const res = await fetch(`${base}/profile`);
  const body = await res.json();
  return body.profile;
}
