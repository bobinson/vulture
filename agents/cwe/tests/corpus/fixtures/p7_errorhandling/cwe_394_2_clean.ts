export async function loadQuota(base: string): Promise<number> {
  const res = await fetch(`${base}/quota`);
  if (res.status !== 200) {
    throw new Error("quota lookup failed");
  }
  const body = await res.json();
  return body.remaining as number;
}
