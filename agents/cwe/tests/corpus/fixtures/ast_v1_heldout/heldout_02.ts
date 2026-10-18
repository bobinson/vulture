// held-out heldout_02 (CWE-918): a POST to a module-constant endpoint whose path ends in a word the regex tier reads as user input
import { createServer } from "node:http";

const ACCOUNT_SERVICE = "accounts-service";

export async function enrolAccount(
  tier: string,
  headers: Record<string, string>,
): Promise<unknown> {
  const enrolBody: Record<string, unknown> = {
    tier,
    meta: { kind: "UNSPECIFIED" },
  };
  const enrolResponse = await fetch(`${ACCOUNT_SERVICE}/v1/enrolUser`, {
    method: "POST",
    headers,
    body: JSON.stringify(enrolBody),
  });
  if (!enrolResponse.ok) {
    throw new Error(`enrol failed: ${enrolResponse.status}`);
  }
  return enrolResponse.json();
}

export function startCallbackListener(): void {
  createServer(() => undefined).listen(0);
}
