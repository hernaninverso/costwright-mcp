#!/usr/bin/env node
/**
 * costwright MCP server
 * ---------------------
 * Static budget analysis for LLM-agent workflows. Points at a Python repo using
 * LangGraph / CrewAI / OpenAI-Agents-SDK and, via pure AST analysis (it NEVER
 * runs the code), reports the worst-case token/superstep budget ceiling: which
 * graph units are certifiable / default-dependent / non-certifiable / runaway,
 * and which LLM constructors have no token cap. Optionally issues an
 * Ed25519-signed budget certificate logged to a public transparency log.
 *
 * Wraps the hosted costwright API (https://costwright-api.eleata.io).
 *
 * Tools:
 *   - costwright_check(repo_path, policy?)        -> POST /v1/check       (free)
 *   - costwright_certify(repo_path, policy?, label?) -> POST /v1/certificates (paid)
 *   - costwright_verify(cert_id)                  -> GET  /v1/verify/{id} (public)
 *   - costwright_pubkey()                         -> GET  /v1/pubkey      (public)
 *
 * Auth (check/certify only): set COSTWRIGHT_API_KEY. Sent as `X-RapidAPI-Key`
 * by default (RapidAPI channel); set COSTWRIGHT_DIRECT=1 to send it as
 * `Authorization: Bearer` against the direct/Paddle channel instead.
 * verify/pubkey are public (no key).
 */
import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { gzipSync } from "node:zlib";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const API_BASE = (process.env.COSTWRIGHT_API_BASE || "https://costwright-api.eleata.io").replace(/\/+$/, "");
const API_KEY = process.env.COSTWRIGHT_API_KEY || "";
const USE_DIRECT = process.env.COSTWRIGHT_DIRECT === "1";
const USER_AGENT = "costwright-mcp/0.1.0";
const TIMEOUT_MS = 45_000; // analysis can take up to ~30s
const EXCLUDE_DIRS = new Set([".venv", "venv", "node_modules", "site-packages", ".git", "__pycache__", "tests", "docs", "build", "dist", ".mypy_cache", ".pytest_cache"]);
const MAX_FILES = 6000;
const MAX_TOTAL_BYTES = 60_000_000;

// ---- minimal tar (ustar) + gzip, .py files only ---------------------------
function collectPyFiles(root: string): { path: string; rel: string }[] {
  const out: { path: string; rel: string }[] = [];
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (EXCLUDE_DIRS.has(name)) continue;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(full);
      else if (st.isFile() && name.endsWith(".py")) out.push({ path: full, rel: relative(root, full).split(sep).join("/") });
      if (out.length > MAX_FILES) return;
    }
  };
  walk(root);
  return out;
}

function tarHeader(name: string, size: number): Buffer {
  const h = Buffer.alloc(512, 0);
  h.write(name.slice(0, 100), 0, "utf8");
  h.write("0000644\0", 100); // mode
  h.write("0000000\0", 108); // uid
  h.write("0000000\0", 116); // gid
  h.write(size.toString(8).padStart(11, "0") + "\0", 124); // size (octal)
  h.write("00000000000\0", 136); // mtime (0 — deterministic)
  h.write("        ", 148); // checksum placeholder (8 spaces)
  h.write("0", 156); // typeflag = regular file
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += h[i];
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

function buildTarGz(root: string): { buf: Buffer; count: number } {
  const files = collectPyFiles(root);
  if (files.length === 0) throw new Error("no .py files found under the given path");
  const chunks: Buffer[] = [];
  let total = 0;
  for (const f of files) {
    const data = readFileSync(f.path);
    total += data.length;
    if (total > MAX_TOTAL_BYTES) throw new Error("repo too large (over 60MB of .py source)");
    chunks.push(tarHeader(f.rel, data.length));
    chunks.push(data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) chunks.push(Buffer.alloc(pad, 0));
  }
  chunks.push(Buffer.alloc(1024, 0)); // two zero blocks = end of archive
  return { buf: gzipSync(Buffer.concat(chunks)), count: files.length };
}

// ---- http helpers ----------------------------------------------------------
function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { "User-Agent": USER_AGENT };
  if (API_KEY) {
    if (USE_DIRECT) h["Authorization"] = `Bearer ${API_KEY}`;
    else h["X-RapidAPI-Key"] = API_KEY;
  }
  return h;
}

async function httpGet(path: string): Promise<{ status: number; text: string } | { error: string }> {
  try {
    const res = await fetch(`${API_BASE}${path}`, { headers: { "User-Agent": USER_AGENT }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    return { status: res.status, text: await res.text() };
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") return { error: `costwright did not respond within ${TIMEOUT_MS / 1000}s` };
    return { error: `could not reach costwright at ${API_BASE}` };
  }
}

async function postArtifact(path: string, root: string, policy: string, label?: string): Promise<string> {
  if (!API_KEY) {
    return "No API key configured. Set COSTWRIGHT_API_KEY. Get one from the costwright RapidAPI listing or the direct channel (https://eleata.io).";
  }
  let tar;
  try {
    tar = buildTarGz(root);
  } catch (e) {
    return `Could not build the source archive: ${(e as Error).message}`;
  }
  const form = new FormData();
  form.append("artifact", new Blob([tar.buf], { type: "application/gzip" }), "artifact.tar.gz");
  form.append("policy", policy);
  if (label) form.append("customer_label", label);

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method: "POST", headers: authHeaders(), body: form, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") return `costwright did not respond within ${TIMEOUT_MS / 1000}s (analysis can take ~30s).`;
    return `Could not reach costwright at ${API_BASE}.`;
  }
  const text = await res.text();
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    return `costwright returned a non-JSON response (HTTP ${res.status}).`;
  }
  if (res.status === 401 || res.status === 403) return "Authentication failed: COSTWRIGHT_API_KEY missing, invalid, or wrong channel.";
  if (res.status === 429) return "costwright is rate-limited or at capacity. Try again shortly.";
  if (res.status < 200 || res.status >= 300) {
    const msg = data?.error?.message || data?.detail || data?.message || `HTTP ${res.status}`;
    return `costwright request failed: ${String(msg).slice(0, 300)}`;
  }
  return `Analyzed ${tar.count} .py file(s).\n` + JSON.stringify(data, null, 2);
}

const TOOLS = [
  {
    name: "costwright_check",
    description:
      "Statically analyze an LLM-agent repo (LangGraph / CrewAI / OpenAI-Agents-SDK) for runaway-budget risk " +
      "WITHOUT running it. Builds a .py-only archive of the given local path and returns a worst-case budget " +
      "summary: counts of certifiable / default_dependent / non_certifiable / runaway graph units and a " +
      "pass|fail verdict. Use before deploying a workflow to catch missing token caps and while-True runaway drivers.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        repo_path: { type: "string", description: "Absolute path to the local Python repo/directory to analyze." },
        policy: { type: "string", enum: ["default", "strict"], default: "default", description: "Analysis policy." },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "costwright_certify",
    description:
      "Issue a tamper-evident, Ed25519-signed budget certificate for an agent repo (re-run server-side, logged " +
      "to a public transparency log). Same input as costwright_check plus an optional label. Returns the cert_id, " +
      "the signed certificate and a verify_url. Use to produce an auditable proof of a workflow's worst-case spend ceiling.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        repo_path: { type: "string", description: "Absolute path to the local Python repo/directory to certify." },
        policy: { type: "string", enum: ["default", "strict"], default: "default" },
        label: { type: "string", description: "Optional human label for the certificate." },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "costwright_verify",
    description: "Verify a previously issued costwright certificate by id (public, no key). Returns its state (valid|expired|revoked|signature_invalid), whether the signature checks out, and the certified result.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { cert_id: { type: "string", description: "The certificate id to verify." } },
      required: ["cert_id"],
    },
  },
  {
    name: "costwright_pubkey",
    description: "Fetch costwright's active Ed25519 public keys (PEM) for offline signature verification of any certificate (public, no key).",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
];

const server = new Server({ name: "costwright", version: "0.1.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: rawArgs } = req.params;
  const args = (rawArgs ?? {}) as Record<string, unknown>;
  try {
    let text: string;
    if (name === "costwright_check") {
      text = await postArtifact("/v1/check", String(args.repo_path ?? ""), String(args.policy ?? "default"));
    } else if (name === "costwright_certify") {
      text = await postArtifact("/v1/certificates", String(args.repo_path ?? ""), String(args.policy ?? "default"), args.label ? String(args.label) : undefined);
    } else if (name === "costwright_verify") {
      const id = String(args.cert_id ?? "");
      if (!id) text = "cert_id is required.";
      else {
        const r = await httpGet(`/v1/verify/${encodeURIComponent(id)}`);
        text = "error" in r ? r.error : r.status >= 200 && r.status < 300 ? r.text : `HTTP ${r.status}: ${r.text.slice(0, 200)}`;
      }
    } else if (name === "costwright_pubkey") {
      const r = await httpGet("/v1/pubkey");
      text = "error" in r ? r.error : r.status >= 200 && r.status < 300 ? r.text : `HTTP ${r.status}: ${r.text.slice(0, 200)}`;
    } else {
      return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
    }
    return { content: [{ type: "text", text }] };
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: `Tool ${name} failed: ${(e as Error).message}` }] };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("costwright MCP server running on stdio\n");
}

main().catch((e) => {
  process.stderr.write(`fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
