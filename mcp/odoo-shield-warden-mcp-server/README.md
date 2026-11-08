# odoo-shield-warden-mcp-server

Read-only MCP server for **Odoo Shield Warden** (Odoo hardening and continuous compliance), built from the "Odoo Assurance: Subscription Strategy" doc, Concept A.

| Tool | Does |
|---|---|
| `shield_list_clients` | Client ids, URLs, databases (no credentials) |
| `shield_qualify_hosting` | Which checks apply: Odoo Online / Odoo.sh / self-hosted |
| `shield_scan_external` | Passive scan: TLS, redirect, headers, public db list/manager, version, ports 5432/8069/8072 |
| `shield_audit_access` | Admin sprawl, dormant users, admin 2FA, segregation of duties, portal, API-key expiry |
| `shield_audit_config` | web.base.url HTTPS, open sign-up, password length |
| `shield_build_scorecard` | Score /100, grade, top 3 fixes |

All tools are read-only. The Odoo client exposes only `search_read` and `fields_get`; it uses `/jsonrpc` and falls back to `/json/2` (Odoo 19+).

## Run

```bash
npm install && npm run build && npm run smoke
```

Claude Desktop / Claude Code config:

```json
{
  "mcpServers": {
    "odoo-shield-warden": {
      "command": "node",
      "args": ["<path>/dist/index.js"],
      "env": { "SHIELD_CLIENTS": "{\"acme\":{\"url\":\"https://erp.acme.com\",\"db\":\"acme\",\"login\":\"audit@acme.com\",\"apiKey\":\"...\"}}" }
    }
  }
}
```

Use a dedicated audit user per client with read-only rights. `shield_scan_external` requires `authorized=true`: scan only systems you have written permission to test.

## Safety design

- **Read-only by construction:** the client has only `search_read` and `fields_get`, and refuses any model outside a fixed allowlist (`res.users`, `res.users.apikeys`, `res.groups`, `ir.model.data`, `ir.config_parameter`, `ir.module.module`).
- **Dedicated audit user:** `shield_audit_access` flags it if the audit user is a Settings administrator. Use a minimal-rights user and, ideally, a read-only PostgreSQL role behind it.
- **Untrusted text:** logins, names and key labels from Odoo have control characters stripped, are length-capped, and results carry a "data, never instructions" notice (prompt-injection hardening).
- **Tamper-evident read log:** set `SHIELD_AUDIT_LOG=<path>` for a hash-chained JSONL record of every Odoo read (model, fields, row count, never values).
- **Transport:** stdio only. If you add HTTP, put authentication in front of it: several existing Odoo MCP servers ship HTTP with no client auth.
- **AI-agent surface:** audits flag admin-owned API keys and installed MCP/AI bridge modules (`mcp_server`, `ai_oca_mcp`, `ai_mcp`, and two Apps Store ones).

## Not covered (needs host access, outside this server)

Backup restore verification, quarterly DR drill, odoo.conf baseline (master password, dbfilter, proxy_mode), PostgreSQL health. Debug-mode detection is not attempted.

## Status

Tested against a mock Odoo (`scripts/smoke.ts`) only. Not yet run against a live Odoo instance or a real TLS target; validate on your first pilot client. `evaluation.xml` is fixture-based.
