// tiny-confirm-gate: a side-effect confirm gate for agent tool calls.
// No API key. No network. Mocked tools only. Run: npx tsx confirm.ts
// Confirm tokens, TTLs, and action payloads below are EXAMPLE INPUTS.

import { createHmac, createHash, randomBytes, timingSafeEqual } from "node:crypto";

type Kind = "read" | "side_effect";

type Action = {
  tool: string;
  method: string;
  target: string;
  body?: Record<string, unknown>;
};

type ConfirmToken = {
  id: string;
  actionHash: string;
  expiresAt: number;
  used: boolean;
};

type GateResult =
  | { ok: true; dryRun?: boolean; detail: string }
  | { ok: false; reason: string; needConfirm?: boolean; actionHash?: string };

const SECRET = Buffer.from("demo-secret-not-for-prod", "utf8");
const TTL_MS = 60_000; // example: 60s confirm window

const tokens = new Map<string, ConfirmToken>();
const audit: string[] = [];

function classify(action: Action): Kind {
  const m = action.method.toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS") return "read";
  // POST, PUT, PATCH, DELETE, and named mutators
  const tools = new Set([
    "form_submit",
    "send_email",
    "charge",
    "file_write",
    "shell_mutate",
    "webhook_post",
  ]);
  if (tools.has(action.tool) || ["POST", "PUT", "PATCH", "DELETE"].includes(m)) {
    return "side_effect";
  }
  return "read";
}

function canonical(action: Action): string {
  const body = action.body
    ? JSON.stringify(action.body, Object.keys(action.body).sort())
    : "";
  return `${action.tool}|${action.method.toUpperCase()}|${action.target}|${body}`;
}

function actionHash(action: Action): string {
  return createHash("sha256").update(canonical(action)).digest("hex");
}

function sign(payload: string): string {
  return createHmac("sha256", SECRET).update(payload).digest("hex");
}

/** Human (or stricter policy) mints a short-lived confirm for the exact payload. */
function mintConfirm(action: Action, now = Date.now()): string {
  const hash = actionHash(action);
  const id = randomBytes(16).toString("hex");
  const expiresAt = now + TTL_MS;
  tokens.set(id, { id, actionHash: hash, expiresAt, used: false });
  const mac = sign(`${id}.${hash}.${expiresAt}`);
  audit.push(`mint  ${action.tool}  hash=${hash.slice(0, 12)}…  ttl=${TTL_MS}ms`);
  return `${id}.${expiresAt}.${mac}`;
}

function parseToken(raw: string): { id: string; expiresAt: number; mac: string } | null {
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  const [id, exp, mac] = parts;
  const expiresAt = Number(exp);
  if (!id || !mac || !Number.isFinite(expiresAt)) return null;
  return { id, expiresAt, mac };
}

function verifyConfirm(action: Action, raw: string | undefined, now = Date.now()): GateResult {
  if (!raw) {
    return {
      ok: false,
      reason: "missing confirm token",
      needConfirm: true,
      actionHash: actionHash(action),
    };
  }
  const parsed = parseToken(raw);
  if (!parsed) return { ok: false, reason: "malformed confirm token" };

  const expectedMac = sign(`${parsed.id}.${actionHash(action)}.${parsed.expiresAt}`);
  const a = Buffer.from(parsed.mac, "hex");
  const b = Buffer.from(expectedMac, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    // Also reject if the token was minted for a different action hash
    const stored = tokens.get(parsed.id);
    if (stored && stored.actionHash !== actionHash(action)) {
      return { ok: false, reason: "confirm token does not match action hash" };
    }
    return { ok: false, reason: "confirm token signature invalid" };
  }

  const stored = tokens.get(parsed.id);
  if (!stored) return { ok: false, reason: "confirm token unknown" };
  if (stored.used) return { ok: false, reason: "confirm token already used" };
  if (now > stored.expiresAt || now > parsed.expiresAt) {
    return { ok: false, reason: "confirm token expired" };
  }
  if (stored.actionHash !== actionHash(action)) {
    return { ok: false, reason: "confirm token does not match action hash" };
  }

  stored.used = true;
  return { ok: true, detail: "confirm accepted (one-time)" };
}

type RunOpts = { confirm?: string; dryRun?: boolean; now?: number };

function run(action: Action, opts: RunOpts = {}): GateResult {
  const kind = classify(action);
  const label = `${action.tool} ${action.method} ${action.target}`;

  if (kind === "read") {
    const detail = opts.dryRun
      ? `dry-run: would READ ${label}`
      : `READ ok: ${mockExecute(action)}`;
    audit.push(`allow ${label}  (${kind})`);
    return { ok: true, dryRun: opts.dryRun, detail };
  }

  // side_effect
  if (opts.dryRun) {
    audit.push(`dry   ${label}  hash=${actionHash(action).slice(0, 12)}…`);
    return {
      ok: true,
      dryRun: true,
      detail: `dry-run: would MUTATE ${label}  body=${JSON.stringify(action.body ?? {})}`,
    };
  }

  const check = verifyConfirm(action, opts.confirm, opts.now ?? Date.now());
  if (!check.ok) {
    audit.push(`block ${label}  (${check.reason})`);
    return check;
  }

  audit.push(`exec  ${label}  (${check.detail})`);
  return { ok: true, detail: `MUTATE ok: ${mockExecute(action)}` };
}

function mockExecute(action: Action): string {
  if (action.tool === "web_fetch" && action.method === "GET") {
    return `fetched ${action.target} (200, mock html)`;
  }
  if (action.tool === "form_submit") {
    return `submitted form → ${action.target}`;
  }
  if (action.tool === "webhook_post") {
    return `posted webhook → ${action.target}`;
  }
  return `ran ${action.tool}`;
}

function show(title: string, result: GateResult) {
  const status = result.ok ? "OK" : "BLOCKED";
  const body = result.ok ? result.detail : result.reason;
  const extra =
    !result.ok && result.needConfirm && result.actionHash
      ? `  needConfirm hash=${result.actionHash.slice(0, 12)}…`
      : "";
  console.log(`[${status}] ${title}`);
  console.log(`         ${body}${extra}`);
}

function main() {
  console.log("tiny-confirm-gate demo");
  console.log("No API key. No network. Example payloads only.\n");

  const getPage: Action = {
    tool: "web_fetch",
    method: "GET",
    target: "https://example.test/help",
  };

  const tipForm: Action = {
    tool: "form_submit",
    method: "POST",
    target: "https://example.test/tips",
    body: {
      note: "example tip text for a demo form",
      name: "",
      contact: "",
    },
  };

  const webhook: Action = {
    tool: "webhook_post",
    method: "POST",
    target: "https://hooks.example.test/agent",
    body: { event: "task_done", id: "demo-1" },
  };

  // 1. Reads pass
  show("1. GET help page", run(getPage));

  // 2. Side effect without confirm
  show("2. submit tip form (no confirm)", run(tipForm));

  // 3. Dry-run shows what would happen
  show("3. dry-run tip form", run(tipForm, { dryRun: true }));

  // 4. Mint confirm for the exact payload, then succeed once
  const token = mintConfirm(tipForm);
  console.log(`\n[minted] confirm token for tip form (truncated)\n`);
  show("4. submit tip form (with confirm)", run(tipForm, { confirm: token }));

  // 5. Replay same token fails (one-time)
  show("5. replay same token", run(tipForm, { confirm: token }));

  // 6. Token minted for tip form does not unlock webhook
  const tipToken2 = mintConfirm(tipForm);
  show("6. webhook with tip-form token", run(webhook, { confirm: tipToken2 }));

  // 7. Matching confirm for webhook succeeds
  const whToken = mintConfirm(webhook);
  show("7. webhook with matching confirm", run(webhook, { confirm: whToken }));

  // 8. Expired token
  const expiredAction: Action = {
    tool: "form_submit",
    method: "POST",
    target: "https://example.test/signup",
    body: { email: "demo@example.test" },
  };
  const oldToken = mintConfirm(expiredAction, Date.now() - TTL_MS - 1_000);
  show(
    "8. submit with expired token",
    run(expiredAction, { confirm: oldToken, now: Date.now() }),
  );

  console.log("\n== audit ==");
  for (const line of audit) console.log(line);
}

main();
