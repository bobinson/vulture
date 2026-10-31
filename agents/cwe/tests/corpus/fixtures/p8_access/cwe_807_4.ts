import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  const secret = request.headers.get("x-action-secret");
  if (secret !== process.env.ACTION_SECRET) {
    return new NextResponse("no", { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    {
      source: "/api/mutations/(.*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
