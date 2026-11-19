import { requireAuth, AuthError } from "@/lib/auth-bridge";
import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  let userId: string;
  try {
    ({ userId } = await requireAuth());
  } catch (error) {
    if (error instanceof AuthError) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    throw error;
  }

  const { id } = await params;
  const engagement = await prisma.engagement.findFirst({ where: { id, userId } });
  if (!engagement) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const password = process.env.NEO4J_PASSWORD;
  if (!password || password === "buggy-graph") {
    return NextResponse.json({ error: "Knowledge graph unavailable" }, { status: 503 });
  }

  const neo4j = await import("neo4j-driver");
  const driver = neo4j.default.driver(
    process.env.NEO4J_URI ?? "bolt://neo4j:7687",
    neo4j.default.auth.basic(process.env.NEO4J_USER ?? "neo4j", password),
  );
  const session = driver.session({ database: "neo4j" });
  try {
    const result = await session.run(
      `MATCH (f:Finding)
       WHERE f.engagement = $engagement
         AND f.published = true
         AND f.closure_state = 'confirmed'
       RETURN f.key AS id, f.label AS title, properties(f) AS props
       ORDER BY f.firstseen`,
      { engagement: engagement.name },
    );
    const findings = result.records.map((record) => {
      const props = record.get("props") as Record<string, unknown>;
      return {
        id: record.get("id"),
        title: record.get("title"),
        severity: props.severity ?? "info",
        description: props.description ?? props.summary ?? "No description available.",
        evidence: props.evidence ?? "No evidence recorded.",
        attackVector: props.poc_script_code ?? "Unknown",
        affectedAssets: props.target ? [props.target] : [],
        cvssScore: props.cvss_score,
        cvssVector: props.cvss_vector,
        cwe: props.cwe,
        mitre: props.mitre,
        remediation: props.remediation,
      };
    });
    return NextResponse.json(findings);
  } catch (error) {
    console.error("Neo4j findings query error:", error instanceof Error ? error.message : error);
    return NextResponse.json({ error: "Knowledge graph unavailable" }, { status: 503 });
  } finally {
    await session.close();
    await driver.close();
  }
}
