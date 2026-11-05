export { default } from "next-auth/middleware";

export const config = {
  matcher: [
    { source: "/dashboard/:path*", missing: [{ type: "header", key: "x-skip-auth" }] },
  ],
};
