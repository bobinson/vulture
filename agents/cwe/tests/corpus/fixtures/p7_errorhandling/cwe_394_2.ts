export async function loadQuota(base: string): Promise<number> {
  const res = await fetch(`${base}/quota`);
  const body = await res.json();
  return body.remaining as number;
}
