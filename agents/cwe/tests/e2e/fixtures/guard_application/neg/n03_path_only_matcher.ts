import { NextResponse, type NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

export default async function gate(req: NextRequest) {
  if (!(await getToken({ req }))) return NextResponse.redirect(new URL("/login", req.url));
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/((?!_next/static|_next/image|favicon.ico).*)"],
};
