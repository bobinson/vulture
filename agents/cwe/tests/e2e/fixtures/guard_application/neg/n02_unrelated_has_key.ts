import { NextResponse, type NextRequest } from "next/server";
const flags = { has: true, missing: [] as string[] };

export function proxy(request: NextRequest) {
  if (request.headers.get("x-action-secret") !== process.env.ACTION_SECRET) {
    return new NextResponse("no", { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ["/api/mutations/:path*"] };
