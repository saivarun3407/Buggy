// One read from one of the stack's MCP servers over streamable HTTP.
//
// The TypeScript twin of buggy/pipeline/mcp_client.py::call_mcp_sync, written
// against `fetch` because the web app carries no MCP SDK: the same bearer
// token header, the same result shape, and an unreachable, unauthenticated or
// misbehaving server is an `{ error }` result, never an exception.
//
// The token is sent to the configured URL only: redirects are refused, so a
// server (or anything in front of it) cannot bounce the token elsewhere.

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface McpCallOptions {
  fetchImpl?: FetchLike;
  /** One deadline for the whole call (handshake and tool call). */
  timeoutMs?: number;
  /** A response larger than this is an error, not a reason to use more memory. */
  maxResponseBytes?: number;
}

export type McpResult = Record<string, unknown>;

const PROTOCOL_VERSION = "2025-03-26";
const DEFAULT_TIMEOUT_MS = 4000;
const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const SESSION_HEADER = "mcp-session-id";

class McpError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The JSON-RPC reply to request `id` in a JSON body or in the text of an event stream. */
export function findRpcReply(
  contentType: string,
  text: string,
  id: number,
): Record<string, unknown> | null {
  const candidates: unknown[] = [];
  if (contentType.includes("text/event-stream")) {
    for (const event of text.split(/\r?\n\r?\n/)) {
      const data = event
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ /, ""))
        .join("\n");
      if (!data) continue;
      try {
        candidates.push(JSON.parse(data));
      } catch {
        // An event still being received, or one that is not JSON.
      }
    }
  } else {
    try {
      candidates.push(JSON.parse(text));
    } catch {
      return null;
    }
  }
  for (const candidate of candidates.flatMap((c) => (Array.isArray(c) ? c : [c]))) {
    if (isRecord(candidate) && candidate.id === id && ("result" in candidate || "error" in candidate)) {
      return candidate;
    }
  }
  return null;
}

async function readReply(response: Response, id: number, maxBytes: number): Promise<Record<string, unknown>> {
  const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
  const reader = response.body?.getReader();
  if (!reader) throw new McpError("the server sent no response body");
  const decoder = new TextDecoder();
  let text = "";
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) {
        received += value.byteLength;
        if (received > maxBytes) throw new McpError("the response is too large");
        text += decoder.decode(value, { stream: true });
        // An event stream may stay open after the reply; do not wait for it to end.
        if (contentType.includes("text/event-stream")) {
          const reply = findRpcReply(contentType, text, id);
          if (reply) return reply;
        }
      }
      if (done) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const reply = findRpcReply(contentType, text + decoder.decode(), id);
  if (!reply) throw new McpError("the server sent no reply to the request");
  return reply;
}

/** A tool result as a plain object, the way `call_mcp_sync` returns it. */
export function toolResultToObject(result: unknown): McpResult {
  if (!isRecord(result)) return { error: "the server returned a tool result that is not an object" };
  const content = Array.isArray(result.content) ? result.content : [];
  const text = content
    .map((item) => (isRecord(item) && typeof item.text === "string" ? item.text : ""))
    .filter(Boolean)
    .join("\n");
  if (result.isError === true) {
    return { error: (text || "the tool call failed").slice(0, 300) };
  }
  let payload: unknown;
  if (isRecord(result.structuredContent)) {
    const structured = result.structuredContent;
    payload = "result" in structured ? structured.result : structured;
  } else {
    try {
      payload = JSON.parse(text || "{}");
    } catch {
      return { error: "the server returned a non-JSON result" };
    }
  }
  return isRecord(payload) ? payload : { result: payload };
}

/**
 * Call `tool` on the MCP server at `url`, presenting `token` as a bearer token.
 * Always resolves: failures come back as `{ error: "..." }`.
 */
export async function callMcpTool(
  url: string,
  token: string,
  tool: string,
  args: Record<string, unknown>,
  options: McpCallOptions = {},
): Promise<McpResult> {
  const doFetch: FetchLike = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return { error: "the server URL is not a valid URL" };
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return { error: "the server URL must be http or https" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let sessionId = "";
  let version = PROTOCOL_VERSION;

  const post = (body: unknown, extra: Record<string, string> = {}) =>
    doFetch(target.href, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        ...extra,
      },
      body: JSON.stringify(body),
      redirect: "error",
      cache: "no-store",
      signal: controller.signal,
    });

  const request = async (id: number, method: string, params: unknown, extra: Record<string, string> = {}) => {
    const response = await post({ jsonrpc: "2.0", id, method, params }, extra);
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new McpError(
        response.status === 401 || response.status === 403
          ? `the server refused the token (HTTP ${response.status})`
          : `the server answered HTTP ${response.status}`,
      );
    }
    const reply = await readReply(response, id, maxBytes);
    if (isRecord(reply.error)) {
      throw new McpError(`${method} failed: ${String(reply.error.message ?? "error").slice(0, 200)}`);
    }
    return { result: reply.result, headers: response.headers };
  };

  try {
    const init = await request(1, "initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "buggy-web", version: "0" },
    });
    sessionId = init.headers.get(SESSION_HEADER) ?? "";
    if (isRecord(init.result) && typeof init.result.protocolVersion === "string") {
      version = init.result.protocolVersion;
    }
    const session: Record<string, string> = { "MCP-Protocol-Version": version };
    if (sessionId) session[SESSION_HEADER] = sessionId;

    const ready = await post({ jsonrpc: "2.0", method: "notifications/initialized" }, session);
    await ready.body?.cancel().catch(() => {});
    if (!ready.ok) throw new McpError(`the server answered HTTP ${ready.status}`);

    const called = await request(2, "tools/call", { name: tool, arguments: args }, session);
    return toolResultToObject(called.result);
  } catch (error) {
    if (controller.signal.aborted) return { error: "the server call timed out" };
    const message = error instanceof Error ? error.message : String(error);
    return { error: `the server call failed: ${message.slice(0, 300)}` };
  } finally {
    clearTimeout(timer);
    if (sessionId) {
      // Best effort: let the server drop the session now rather than at its own timeout.
      await doFetch(target.href, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
          "MCP-Protocol-Version": version,
          [SESSION_HEADER]: sessionId,
        },
        redirect: "error",
        signal: AbortSignal.timeout(1000),
      })
        .then((response) => response.body?.cancel())
        .catch(() => {});
    }
  }
}
