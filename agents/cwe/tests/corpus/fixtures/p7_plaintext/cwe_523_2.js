export async function login(user, pass) {
  const blob = Buffer.from(`${user}:${pass}`).toString("base64");
  const resp = await fetch("http://api.corp.example/v1/session", {
    headers: { Authorization: `Basic ${blob}` },
  });
  return resp.json();
}
