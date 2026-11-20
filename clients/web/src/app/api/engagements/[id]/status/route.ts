import { requireAuth, AuthError } from "@/lib/auth-bridge";
import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";
import { rootsFromEnv, statusResponse, toolFetchFromEnv } from "./snapshot";

// Read-only: the snapshot `buggy-cli status` prints, for the run page. The
// logic lives in ./snapshot.ts so it can be tested without a database.
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  let userId: string;
  try {
    ({ userId } = await requireAuth());
  } catch (e) {
    if (e instanceof AuthError) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    throw e;
  }

  const { id } = await params;
  const { status, body } = await statusResponse(id, {
    findEngagement: (engagementId) =>
      prisma.engagement.findFirst({ where: { id: engagementId, userId } }),
    roots: rootsFromEnv(process.env),
    fetchTool: toolFetchFromEnv(process.env),
  });
  return NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });
}
