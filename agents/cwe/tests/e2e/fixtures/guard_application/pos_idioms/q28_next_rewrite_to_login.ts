import { NextResponse } from "next/server";

export function middleware(req) {
  const token = req.cookies.get("session")?.value;
  if (!token) {
    return NextResponse.rewrite(new URL("/login", req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    {
      source: "/account/:path*",
      missing: [{ type: "query", key: "share" }],
    },
  ],
};
