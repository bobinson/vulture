import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  if (request.headers.get("x-action-secret") !== process.env.ACTION_SECRET) {
    return new NextResponse("no", { status: 403 });
  }
  return NextResponse.next();
}

/*
 * Old config, kept for reference:
 * export const config = { matcher: [{ source: "/api/(.*)",
 *   missing: [{ type: "header", key: "next-router-prefetch" }] }] };
 */
export const config = { matcher: ["/api/:path*"] };
