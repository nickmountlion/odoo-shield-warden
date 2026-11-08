#!/usr/bin/env node
/**
 * Odoo Shield Warden MCP server: read-only Odoo hardening and continuous-compliance audits.
 * Stdio transport. Client credentials come from the SHIELD_CLIENTS environment variable.
 */
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { auditAccess, auditConfig, DEFAULT_SOD_PAIRS, scorecard } from "./audit.js";
import { getClient, loadClients, OdooReadOnly } from "./odoo.js";
import { scanExternal } from "./scan.js";
import { CHARACTER_LIMIT, FindingSchema, ResponseFormat, SEVERITY_ORDER, UNTRUSTED_NOTICE, type Finding } from "./types.js";

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true } as const;
const FormatField = z.enum(ResponseFormat).default(ResponseFormat.MARKDOWN).describe("'markdown' for readable text, 'json' for structured data");

const HOSTING = {
  online: { label: "Odoo Online (SaaS)", access: "No server access", applicable: ["shield_scan_external", "shield_audit_access", "shield_audit_config"], not_applicable: ["Backup restore verification", "PostgreSQL health", "OS patching", "odoo.conf baseline"] },
  odoosh: { label: "Odoo.sh", access: "Limited infrastructure access", applicable: ["shield_scan_external", "shield_audit_access", "shield_audit_config"], not_applicable: ["OS patching", "Direct PostgreSQL tuning (use Odoo.sh tools)"] },
  self_hosted: { label: "Self-hosted / VM (AWS, Azure, on-prem)", access: "Full scope", applicable: ["shield_scan_external", "shield_audit_access", "shield_audit_config"], not_applicable: [] }
} as const;

function render(title: string, findings: Finding[], format: ResponseFormat) {
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const build = (items: Finding[]) => {
    const card = scorecard(findings);
    const payload = { title, notice: UNTRUSTED_NOTICE, ...card, total: findings.length, shown: items.length, findings: items };
    if (format === ResponseFormat.JSON) return { payload, text: JSON.stringify(payload, null, 2) };
    const lines = [`# ${title}`, `Score **${card.score}/100 (grade ${card.grade})**. ` + SEVERITY_ORDER.map(s => `${card.counts[s]} ${s}`).join(", ") + ".", `_${UNTRUSTED_NOTICE}_`, ""];
    for (const f of items) lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`, f.detail, `**Fix:** ${f.fix}`, "");
    if (items.length < findings.length) lines.push(`_${findings.length - items.length} lower-severity findings omitted to fit the size limit; use response_format=json._`);
    return { payload, text: lines.join("\n") };
  };
  let items = sorted;
  let out = build(items);
  while (items.length > 1 && out.text.length > CHARACTER_LIMIT) {
    items = items.slice(0, Math.ceil(items.length / 2));
    out = build(items);
  }
  return format === ResponseFormat.JSON
    ? { content: [{ type: "text" as const, text: out.text }], structuredContent: out.payload }
    : { content: [{ type: "text" as const, text: out.text }] };
}

function createServer(): McpServer {
  const server = new McpServer({ name: "odoo-shield-warden-mcp-server", version: "1.0.0" });

  server.registerTool(
    "shield_list_clients",
    {
      title: "List Shield Clients",
      description: "List the client ids configured in SHIELD_CLIENTS with their Odoo URL and database (never credentials). Use these ids with shield_audit_access and shield_audit_config.",
      inputSchema: z.strictObject({}),
      annotations: { ...READ_ONLY, openWorldHint: false }
    },
    async () => {
      const rows = Object.entries(loadClients()).map(([id, c]) => `- ${id}: ${c.url} (db: ${c.db})`);
      return { content: [{ type: "text", text: rows.length ? rows.join("\n") : "No clients configured. Set SHIELD_CLIENTS (JSON map of id -> {url, db, login, apiKey})." }] };
    }
  );

  server.registerTool(
    "shield_qualify_hosting",
    {
      title: "Qualify Hosting Model",
      description: `Say which Shield checks apply to a client, based on where Odoo runs. Do this first for every lead: the hosting model decides the scope.

Examples:
  - "Client is on Odoo Online" -> hosting="online"
  - "Client runs Odoo on an AWS VM" -> hosting="self_hosted"`,
      inputSchema: z.strictObject({ hosting: z.enum(["online", "odoosh", "self_hosted"]).describe("Where the client's Odoo runs") }),
      annotations: { ...READ_ONLY, openWorldHint: false }
    },
    async ({ hosting }) => {
      const h = HOSTING[hosting];
      const text = [`# ${h.label}`, `Access: ${h.access}`, "", "**Checks that apply:** " + h.applicable.join(", "), "", "**Out of reach:** " + (h.not_applicable.join(", ") || "nothing"), "", "Backup restore verification and DR drills run outside this server."].join("\n");
      return { content: [{ type: "text", text }] };
    }
  );

  server.registerTool(
    "shield_scan_external",
    {
      title: "External Attack-Surface Scan",
      description: `Passive external scan of an Odoo URL: TLS certificate and protocol, HTTP->HTTPS redirect, security headers, public database list/manager, version disclosure, and reachability of ports 5432, 8069 and 8072. Sends only GET/one empty JSON-RPC calls and TCP connects; no exploitation.

Only scan systems you are authorised to test: set authorized=true to confirm. Returns findings with severity and plain-language fixes.

Example: "Scan https://erp.acme.com" -> url="https://erp.acme.com", authorized=true`,
      inputSchema: z.strictObject({
        url: z.url().describe("Base URL of the Odoo instance, e.g. 'https://erp.acme.com'"),
        authorized: z.literal(true).describe("Must be true: confirms written authorisation to scan this target"),
        response_format: FormatField
      }),
      annotations: { ...READ_ONLY, openWorldHint: true }
    },
    async ({ url, response_format }, ctx) => render(`External scan: ${new URL(url).host}`, await scanExternal(url, ctx.mcpReq.signal), response_format)
  );

  server.registerTool(
    "shield_audit_access",
    {
      title: "Access-Rights Audit",
      description: `Read-only audit of one client's users via the Odoo API: Settings/admin sprawl, dormant accounts, 2FA on administrators, segregation-of-duties conflicts, portal exposure and API-key expiry. The audit user needs read access to res.users, ir.model.data and ideally res.users.apikeys.

Use shield_list_clients to find client ids. Example: "Who has admin rights at acme?" -> client="acme"`,
      inputSchema: z.strictObject({
        client: z.string().min(1).describe("Client id from SHIELD_CLIENTS"),
        dormant_days: z.number().int().min(7).max(730).default(90).describe("Days without login before an account counts as dormant"),
        sod_pairs: z.array(z.tuple([z.string(), z.string()])).max(20).optional().describe("Group xml-id pairs no single user should hold, e.g. [['purchase.group_purchase_manager','account.group_account_manager']]. Defaults to purchase/stock manager vs accounting manager."),
        response_format: FormatField
      }),
      annotations: { ...READ_ONLY, openWorldHint: true }
    },
    async ({ client, dormant_days, sod_pairs, response_format }, ctx) => {
      const config = getClient(client);
      const odoo = new OdooReadOnly(config, ctx.mcpReq.signal);
      return render(`Access-rights audit: ${client}`, await auditAccess(odoo, dormant_days, sod_pairs ?? DEFAULT_SOD_PAIRS, config.login), response_format);
    }
  );

  server.registerTool(
    "shield_audit_config",
    {
      title: "Configuration Baseline Audit",
      description: "Read-only check of the Odoo system parameters visible through the API: HTTPS base URL, open sign-up and password length. odoo.conf settings (master password, list_db, dbfilter, proxy_mode) are not visible via the API: shield_scan_external covers list_db, and the rest need the baseline audit on the host.",
      inputSchema: z.strictObject({ client: z.string().min(1).describe("Client id from SHIELD_CLIENTS"), response_format: FormatField }),
      annotations: { ...READ_ONLY, openWorldHint: true }
    },
    async ({ client, response_format }, ctx) => {
      const odoo = new OdooReadOnly(getClient(client), ctx.mcpReq.signal);
      return render(`Configuration baseline: ${client}`, await auditConfig(odoo), response_format);
    }
  );

  server.registerTool(
    "shield_build_scorecard",
    {
      title: "Build Monthly Scorecard",
      description: "Combine findings from shield_scan_external, shield_audit_access and shield_audit_config (pass their JSON 'findings') into one scorecard: score out of 100, grade, severity counts and the top three fixes in plain language.",
      inputSchema: z.strictObject({
        client_name: z.string().min(1).max(100).describe("Client name for the scorecard heading"),
        findings: z.array(FindingSchema).min(1).max(500).describe("Findings arrays from the audit tools, concatenated"),
        response_format: FormatField
      }),
      annotations: { ...READ_ONLY, openWorldHint: false }
    },
    async ({ client_name, findings, response_format }) => {
      const card = scorecard(findings);
      if (response_format === ResponseFormat.JSON) {
        const payload = { client: client_name, ...card };
        return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }], structuredContent: payload };
      }
      const lines = [`# Shield scorecard: ${client_name}`, `**${card.score}/100, grade ${card.grade}**`, "", "## Top 3 fixes"];
      card.top_fixes.forEach((f, i) => lines.push(`${i + 1}. **${f.title}** (${f.severity}): ${f.fix}`));
      if (!card.top_fixes.length) lines.push("Nothing to fix this month.");
      lines.push("", "_This score measures what was checked and is not a guarantee of security._");
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  return server;
}

serveStdio(createServer);
console.error("odoo-shield-warden-mcp-server running on stdio");
