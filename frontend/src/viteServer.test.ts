import { describe, expect, it } from "vitest";
import viteConfig from "../vite.config";

// The dev server proxies /api to a backend that, in local mode, serves the
// local user without a password. It must therefore be reachable from this
// machine only, and every proxied request must carry the real client address
// so the backend can refuse anything relayed for another machine.
describe("vite dev server exposure", () => {
  const server = viteConfig.server ?? {};
  const proxy = (server.proxy ?? {}) as Record<string, { xfwd?: boolean }>;

  it("listens on loopback only", () => {
    expect(server.host).toBe("127.0.0.1");
  });

  it("fails instead of silently moving to another port", () => {
    // A stale (possibly outdated) dev server holding the port must not keep
    // serving while the fresh one quietly starts elsewhere.
    expect(server.strictPort).toBe(true);
  });

  it.each(["/api", "/health"])("records the client address on %s", (path) => {
    expect(proxy[path]?.xfwd).toBe(true);
  });
});
