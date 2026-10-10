import { NextResponse, type NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

export default async function gate(req: NextRequest) {
  const token = await getToken({ req });
  if (!token) return NextResponse.redirect(new URL("/login", req.url));
  return NextResponse.next();
}

export const config = { matcher: [{ source: "/dashboard/:path*", has: [{ type: "cookie", key: "beta" }] }] };
