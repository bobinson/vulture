import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
const matcher = [{ source: "/admin/:path*", missing: [{ type: "header", key: "x-skip" }] }];
export const config = { runtime: "nodejs", matcher, };
export async function middleware(req) {
  if (!(await auth(req))) return NextResponse.redirect(new URL("/login", req.url));
}
