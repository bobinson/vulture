import nextAuthMiddleware from "next-auth/middleware";
export default nextAuthMiddleware;
export const config = {
  matcher: [{ source: "/admin/:path*", missing: [{ type: "header", key: "next-router-prefetch" }] }],
};
