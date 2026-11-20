import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { callMcpTool, findRpcReply, toolResultToObject } from "./mcp";
import { reconFromSummary, toolFetchFromEnv } from "./snapshot";

// A small stand-in for a stack MCP server (FastMCP over streamable HTTP behind
// BearerAuth, buggy/pipeline/mcp_http.py): real HTTP, bearer token, a session
// id from `initialize`, replies as an event stream or as plain JSON.

const TOKEN = "t".repeat(32);
const SESSION = "session-abc";
const SUMMARY = {
  engagement: "acme-test",
  records: { url: 12 },
  current_run: { run_id: "r1", started_at: 1000, stage: "dns", stages_done: ["enumerate"] },
  last_run: null,
};

interface Seen {
  method: string;
  rpc: string;
  authorization: string;
  session: string;
  args?: unknown;
}

let server: http.Server;
let elsewhere: http.Server;
let url: string;
let seen: Seen[] = [];
let elsewhereHits: { authorization: string }[] = [];
let mode: "sse" | "json" | "hang" | "redirect" | "tool-error" | "no-session" = "sse";

function listen(handler: http.RequestListener): Promise<http.Server> {
  return new Promise((resolve) => {
    const created = http.createServer(handler);
    created.listen(0, "127.0.0.1", () => resolve(created));
  });
}

function port(of: http.Server): number {
  return (of.address() as AddressInfo).port;
}

before(async () => {
  elsewhere = await listen((req, res) => {
    elsewhereHits.push({ authorization: req.headers.authorization ?? "" });
    res.writeHead(200, { "content-type": "application/json" }).end("{}");
  });
  server = await listen((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const message = raw ? JSON.parse(raw) : {};
      seen.push({
        method: req.method ?? "",
        rpc: message.method ?? "",
        authorization: req.headers.authorization ?? "",
        session: String(req.headers["mcp-session-id"] ?? ""),
        args: message.params?.arguments,
      });
      if (req.headers.authorization !== `Bearer ${TOKEN}`) {
        res.writeHead(401, { "content-type": "application/json" }).end('{"error":"unauthorized"}');
        return;
      }
      if (mode === "redirect") {
        res.writeHead(307, { location: `http://127.0.0.1:${port(elsewhere)}/mcp` }).end();
        return;
      }
      if (mode === "hang") return; // never answers
      if (req.method === "DELETE") {
        res.writeHead(200).end();
        return;
      }
      const reply = (result: unknown, headers: Record<string, string> = {}) => {
        const body = JSON.stringify({ jsonrpc: "2.0", id: message.id, result });
        if (mode === "json") {
          res.writeHead(200, { "content-type": "application/json", ...headers }).end(body);
        } else {
          res.writeHead(200, { "content-type": "text/event-stream", ...headers });
          res.end(`event: message\r\ndata: ${body}\r\n\r\n`);
        }
      };
      if (message.method === "initialize") {
        reply(
          { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "buggy-recon", version: "1" } },
          mode === "no-session" ? {} : { "mcp-session-id": SESSION },
        );
      } else if (message.method === "notifications/initialized") {
        res.writeHead(202).end();
      } else if (message.method === "tools/call") {
        if (mode !== "no-session" && req.headers["mcp-session-id"] !== SESSION) {
          res.writeHead(400).end("Bad Request: Missing session ID");
        } else if (mode === "tool-error") {
          reply({ isError: true, content: [{ type: "text", text: "Unknown tool: nope" }] });
        } else {
          reply({ content: [{ type: "text", text: JSON.stringify(SUMMARY) }], structuredContent: SUMMARY });
        }
      } else {
        res.writeHead(400).end();
      }
    });
  });
  url = `http://127.0.0.1:${port(server)}/mcp`;
});

after(() => {
  server.closeAllConnections();
  server.close();
  elsewhere.close();
});

function reset(next: typeof mode) {
  mode = next;
  seen = [];
  elsewhereHits = [];
}

test("a tool call does the handshake, presents the token and returns the tool's object", async () => {
  for (const variant of ["sse", "json"] as const) {
    reset(variant);
    const result = await callMcpTool(url, TOKEN, "recon_summary", { engagement: "acme-test" });
    assert.deepEqual(result, SUMMARY, variant);
    assert.deepEqual(
      seen.map((s) => `${s.method} ${s.rpc}`),
      ["POST initialize", "POST notifications/initialized", "POST tools/call", "DELETE "],
    );
    assert.ok(seen.every((s) => s.authorization === `Bearer ${TOKEN}`));
    assert.deepEqual(
      seen.map((s) => s.session),
      ["", SESSION, SESSION, SESSION],
    );
    assert.deepEqual(seen[2].args, { engagement: "acme-test" });
  }
});

test("a server without sessions is called without a session id and nothing is deleted", async () => {
  reset("no-session");
  assert.deepEqual(await callMcpTool(url, TOKEN, "recon_summary", {}), SUMMARY);
  assert.deepEqual(
    seen.map((s) => s.method),
    ["POST", "POST", "POST"],
  );
});

test("the recon section is read through the configured server", async () => {
  reset("sse");
  const fetchTool = toolFetchFromEnv({ BUGGY_MCP_RECON_URL: url, BUGGY_STACK_MCP_TOKEN: TOKEN });
  const recon = reconFromSummary(await fetchTool("recon", "recon_summary", { engagement: "acme-test" }), 1090);
  assert.deepEqual(recon, {
    available: true,
    state: "running",
    stage: "dns",
    stages_done: ["enumerate"],
    started_at: 1000,
    elapsed_s: 90,
    records: { url: 12 },
    scope_drops: null,
  });
  // The capture server has no URL here: it is not asked, whatever the token.
  const capture = await fetchTool("capture", "findings_list", { engagement: "acme-test" });
  assert.equal(capture.error, "the capture server is not configured (BUGGY_MCP_CAPTURE_URL)");
  assert.equal(seen.filter((s) => s.rpc === "tools/call").length, 1);
});

test("a wrong token is an error result, not an exception and not data", async () => {
  reset("sse");
  const result = await callMcpTool(url, "wrong-token-wrong-token", "recon_summary", {});
  assert.deepEqual(Object.keys(result), ["error"]);
  assert.match(String(result.error), /refused the token \(HTTP 401\)/);
  assert.equal(seen.length, 1);
});

test("a redirect is refused, so the token is never sent to another host", async () => {
  reset("redirect");
  const result = await callMcpTool(url, TOKEN, "recon_summary", {});
  assert.match(String(result.error), /the server call failed/);
  assert.deepEqual(elsewhereHits, []);
});

test("a server that does not answer is a timeout error", async () => {
  reset("hang");
  const started = Date.now();
  const result = await callMcpTool(url, TOKEN, "recon_summary", {}, { timeoutMs: 150 });
  assert.deepEqual(result, { error: "the server call timed out" });
  assert.ok(Date.now() - started < 3000);
});

test("a tool error, an oversized reply and an unusable URL are error results", async () => {
  reset("tool-error");
  assert.deepEqual(await callMcpTool(url, TOKEN, "nope", {}), { error: "Unknown tool: nope" });

  reset("sse");
  const small = await callMcpTool(url, TOKEN, "recon_summary", {}, { maxResponseBytes: 20 });
  assert.match(String(small.error), /too large/);

  reset("sse");
  for (const bad of ["file:///etc/passwd", "not a url", ""]) {
    const result = await callMcpTool(bad, TOKEN, "recon_summary", {});
    assert.equal(typeof result.error, "string", bad);
  }
  assert.deepEqual(seen, []);

  const refused = await callMcpTool("http://127.0.0.1:1/mcp", TOKEN, "recon_summary", {});
  assert.match(String(refused.error), /the server call failed/);
});

test("findRpcReply picks the reply to the request out of a stream or a JSON body", () => {
  const stream =
    'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/message","params":{}}\n\n' +
    'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}\n\n';
  assert.deepEqual(findRpcReply("text/event-stream", stream, 2), { jsonrpc: "2.0", id: 2, result: { ok: true } });
  assert.equal(findRpcReply("text/event-stream", stream, 3), null);
  assert.equal(findRpcReply("text/event-stream", 'data: {"jsonrpc":"2.0","id":2,"resu', 2), null);
  assert.deepEqual(findRpcReply("application/json", '[{"id":1,"result":1},{"id":2,"error":{}}]', 2), {
    id: 2,
    error: {},
  });
  assert.equal(findRpcReply("application/json", "<html>", 2), null);
});

test("toolResultToObject mirrors the Python client's result shape", () => {
  assert.deepEqual(toolResultToObject({ structuredContent: { result: { a: 1 } } }), { a: 1 });
  assert.deepEqual(toolResultToObject({ structuredContent: { a: 1 } }), { a: 1 });
  assert.deepEqual(toolResultToObject({ content: [{ type: "text", text: '{"a":2}' }] }), { a: 2 });
  assert.deepEqual(toolResultToObject({ content: [{ type: "text", text: "[1,2]" }] }), { result: [1, 2] });
  assert.deepEqual(toolResultToObject({ content: [{ type: "text", text: "plain words" }] }), {
    error: "the server returned a non-JSON result",
  });
  assert.deepEqual(toolResultToObject({ content: [] }), {});
  assert.equal(typeof toolResultToObject("nope").error, "string");
});
