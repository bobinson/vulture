import { readOwnFile } from "@/lib/files";

export async function GET(request: Request): Promise<Response> {
  const { searchParams } = new URL(request.url);
  const body = readOwnFile(searchParams.get("file") ?? "");
  return new Response(body);
}
