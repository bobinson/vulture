import { withAuth } from "next-auth/middleware";

export default withAuth({
  pages: { signIn: "/login" },
});

export const config = {
  matcher: [
    { source: "/dashboard/:path*", missing: [{ type: "header", key: "x-skip" }] },
  ],
};
