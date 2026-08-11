/** session-firewall — local reverse-proxy sandbox by zAx4hub */
export type Request = { method: string; url: string; headers?: Record<string, string>; body?: string };
export type RuleResult = {
  id: string;
  action: "allow" | "block" | "scrub";
  reason: string;
  risk: number;
  scrubbedHeaders?: string[];
};
export type Report = {
  project: string;
  author: string;
  summary: string;
  score: number;
  findings: RuleResult[];
  metrics: Record<string, number>;
};

const BANKING_HOSTS = ["bank.", "paypal.", "stripe.com", "chase.com", "wellsfargo."];

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function isBanking(url: string): boolean {
  const h = hostOf(url);
  return BANKING_HOSTS.some((b) => h.includes(b.replace(/\.$/, "")) || h.endsWith(b.replace(/^\./, "")));
}

export function classify(req: Request, mode: "strict" | "banking" | "permissive" = "banking"): RuleResult {
  const host = hostOf(req.url);
  const headers = Object.fromEntries(Object.entries(req.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  const scrubbed: string[] = [];
  let risk = 0.1;
  if (mode === "banking" && isBanking(req.url)) {
    risk += 0.5;
    if (headers["cookie"]) scrubbed.push("cookie");
    if (headers["authorization"]) scrubbed.push("authorization");
    if (req.method !== "GET" && req.method !== "HEAD") {
      return { id: "banking-write-block", action: "block", reason: `Blocked ${req.method} to banking host ${host}`, risk: 1, scrubbedHeaders: scrubbed };
    }
    return { id: "banking-scrub", action: "scrub", reason: `Scrubbed session headers for ${host}`, risk: 0.7, scrubbedHeaders: scrubbed };
  }
  if (/malware|exfil|pastebin\.com/.test(req.url)) {
    return { id: "deny-list", action: "block", reason: "URL matched deny list", risk: 1 };
  }
  if (mode === "strict" && !headers["x-session-firewall"]) {
    return { id: "missing-marker", action: "block", reason: "Missing sandbox marker header", risk: 0.8 };
  }
  if (headers["cookie"] && mode !== "permissive") {
    scrubbed.push("cookie");
    risk += 0.2;
    return { id: "cookie-scrub", action: "scrub", reason: "Cookie stripped in sandbox", risk, scrubbedHeaders: scrubbed };
  }
  return { id: "allow", action: "allow", reason: "Request permitted", risk };
}

export function run(input: { requests?: Request[]; mode?: "strict" | "banking" | "permissive" } = {}): Report {
  const requests =
    input.requests ??
    [
      { method: "GET", url: "https://bank.example/login", headers: { cookie: "sid=1", authorization: "Bearer x" } },
      { method: "POST", url: "https://chase.com/transfer", headers: { cookie: "sid=1" }, body: "{}" },
      { method: "GET", url: "https://example.com/", headers: { "x-session-firewall": "1" } },
    ];
  const findings = requests.map((r) => classify(r, input.mode ?? "banking"));
  const blocked = findings.filter((f) => f.action === "block").length;
  const score = Math.round((findings.reduce((a, f) => a + f.risk, 0) / findings.length) * 1000) / 1000;
  return {
    project: "session-firewall",
    author: "zAx4hub",
    summary: `Proxied ${findings.length} requests; blocked=${blocked}`,
    score,
    findings,
    metrics: {
      count: findings.length,
      blocked,
      scrubbed: findings.filter((f) => f.action === "scrub").length,
      allowed: findings.filter((f) => f.action === "allow").length,
    },
  };
}

export function demo(): Report {
  return run({ mode: "banking" });
}

export function inspect() {
  return {
    name: "session-firewall",
    author: "zAx4hub",
    oneLiner: "Local reverse proxy sandbox (banking mode)",
    features: ["banking-mode", "deny-list", "header-scrub", "strict-marker", "risk-score"],
    version: "0.1.0",
    commands: ["demo", "run", "inspect"],
  };
}
