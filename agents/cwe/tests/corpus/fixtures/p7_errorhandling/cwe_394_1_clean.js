export async function loadProfile(base) {
  const res = await fetch(`${base}/profile`);
  if (!res.ok) {
    throw new Error(`profile lookup failed: ${res.status}`);
  }
  const body = await res.json();
  return body.profile;
}
