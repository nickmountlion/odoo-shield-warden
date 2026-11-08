import { clean, SEVERITY_ORDER } from "./types.js";
export const DEFAULT_SOD_PAIRS = [
    ["purchase.group_purchase_manager", "account.group_account_manager"],
    ["stock.group_stock_manager", "account.group_account_manager"]
];
async function groupIds(odoo) {
    const rows = await odoo.searchRead("ir.model.data", [["model", "=", "res.groups"]], ["module", "name", "res_id"]);
    return new Map(rows.map(r => [`${r.module}.${r.name}`, r.res_id]));
}
const list = (items, max = 10) => items.slice(0, max).map(i => clean(i)).join(", ") + (items.length > max ? `, +${items.length - max} more` : "");
export async function auditAccess(odoo, dormantDays, sodPairs, auditLogin) {
    const fields = await odoo.fieldNames("res.users");
    const groupsField = fields.has("group_ids") ? "group_ids" : "groups_id"; // renamed in Odoo 19
    const wanted = ["name", "login", "login_date", groupsField, ...(fields.has("totp_enabled") ? ["totp_enabled"] : [])];
    const [internal, portal, ids] = await Promise.all([
        odoo.searchRead("res.users", [["share", "=", false]], wanted),
        odoo.searchRead("res.users", [["share", "=", true]], ["login"]),
        groupIds(odoo)
    ]);
    const findings = [];
    const inGroup = (u, xmlid) => ids.has(xmlid) && (u[groupsField] ?? []).includes(ids.get(xmlid));
    // The audit user itself should be a minimal-rights bot, not an administrator
    const me = internal.find(u => u.login === auditLogin);
    if (me && inGroup(me, "base.group_system"))
        findings.push({ id: "access.audit_user_admin", severity: "medium", title: "The audit user is a Settings administrator", detail: `Shield is connected as ${clean(me.login)}, which holds full admin rights. A leaked key would grant full control.`, fix: "Create a dedicated read-only audit user with no Settings group and issue its API key instead." });
    // Admin sprawl
    const admins = internal.filter(u => inGroup(u, "base.group_system"));
    const adminRatio = internal.length ? admins.length / internal.length : 0;
    const sprawl = admins.length > 5 || (internal.length >= 5 && adminRatio > 0.2) ? "high" : admins.length > 3 ? "medium" : "info";
    findings.push({
        id: "access.admins", severity: sprawl,
        title: `${admins.length} of ${internal.length} internal users are Settings administrators`,
        detail: `Administrators: ${list(admins.map(u => String(u.login)))}.`,
        fix: "Keep Settings access to 2-3 named people; give everyone else only the app roles they use."
    });
    const managers = internal.filter(u => inGroup(u, "base.group_erp_manager") && !inGroup(u, "base.group_system"));
    if (managers.length > 5)
        findings.push({ id: "access.erp_managers", severity: "low", title: `${managers.length} users have Access Rights (ERP manager)`, detail: `Users: ${list(managers.map(u => String(u.login)))}.`, fix: "Limit who can edit users and groups." });
    // Dormant accounts
    const cutoff = Date.now() - dormantDays * 86_400_000;
    const dormant = internal.filter(u => !u.login_date || new Date(`${u.login_date}Z`).getTime() < cutoff);
    if (dormant.length)
        findings.push({ id: "access.dormant", severity: dormant.some(u => inGroup(u, "base.group_system")) ? "high" : "medium", title: `${dormant.length} active accounts with no login in ${dormantDays} days`, detail: `Accounts: ${list(dormant.map(u => String(u.login)))}.`, fix: "Archive accounts of people who left or no longer need access." });
    // 2FA
    if (fields.has("totp_enabled")) {
        const noTotp = admins.filter(u => !u.totp_enabled);
        if (noTotp.length)
            findings.push({ id: "access.2fa_admins", severity: "high", title: `${noTotp.length} administrators have no two-factor authentication`, detail: `Accounts: ${list(noTotp.map(u => String(u.login)))}.`, fix: "Enable 2FA for every administrator, then require it for all users." });
    }
    else {
        findings.push({ id: "access.2fa_missing", severity: "medium", title: "Two-factor authentication module is not installed", detail: "The 'auth_totp' fields are absent from res.users.", fix: "Install 'Two-factor Authentication' and enrol all administrators." });
    }
    // Segregation of duties
    for (const [a, b] of sodPairs) {
        const both = internal.filter(u => inGroup(u, a) && inGroup(u, b));
        if (both.length)
            findings.push({ id: `access.sod.${a}+${b}`, severity: "medium", title: `${both.length} users hold both ${a} and ${b}`, detail: `Users: ${list(both.map(u => String(u.login)))}. One person can both create and approve.`, fix: "Split these roles between two people or add an approval step." });
    }
    findings.push({ id: "access.portal", severity: "info", title: `${portal.length} portal/external users`, detail: "External accounts can reach portal pages; verify record rules if this number is surprising.", fix: "Review portal-facing record rules and archive stale external users." });
    // API keys (admin-only model; absence of access is not a finding)
    try {
        const keys = await odoo.searchRead("res.users.apikeys", [], ["name", "user_id", "create_date", "expiration_date"]);
        const forever = keys.filter(k => !k.expiration_date);
        findings.push({ id: "access.apikeys", severity: forever.length ? "medium" : "info", title: `${keys.length} API keys, ${forever.length} without expiry`, detail: forever.length ? `Non-expiring keys: ${list(forever.map(k => String(k.name)))}.` : "All keys expire.", fix: "Give integration keys an expiry date and rotate them; delete unused keys." });
        const adminIds = new Set(admins.map(u => u.id));
        const adminKeys = keys.filter(k => adminIds.has(Array.isArray(k.user_id) ? k.user_id[0] : k.user_id));
        if (adminKeys.length)
            findings.push({ id: "access.apikeys_admin", severity: "high", title: `${adminKeys.length} API keys belong to administrators`, detail: `Keys: ${list(adminKeys.map(k => String(k.name)))}. An integration or AI agent holding an admin key can change anything.`, fix: "Move integrations and AI agents to dedicated least-privilege users." });
    }
    catch {
        findings.push({ id: "access.apikeys", severity: "info", title: "API key inventory not readable", detail: "The audit user cannot read res.users.apikeys.", fix: "Grant the audit user read access to API keys, or review them in Settings > Users." });
    }
    return findings;
}
export async function auditConfig(odoo) {
    const rows = await odoo.searchRead("ir.config_parameter", [["key", "in", ["web.base.url", "auth_signup.allow_uninvited", "auth_password_policy.minlength"]]], ["key", "value"]);
    const p = new Map(rows.map(r => [String(r.key), String(r.value)]));
    const findings = [];
    // AI/MCP bridge modules widen what an API key can reach
    try {
        const mods = await odoo.searchRead("ir.module.module", [["name", "in", MCP_MODULES], ["state", "=", "installed"]], ["name"]);
        if (mods.length)
            findings.push({ id: "cfg.mcp_modules", severity: "medium", title: `${mods.length} MCP/AI bridge modules installed`, detail: `Modules: ${list(mods.map(m => String(m.name)))}. They let AI agents call Odoo; check their model allowlists exclude payments, bank accounts, users and system parameters.`, fix: "Restrict each bridge to read-only on the models it needs, and run it as a minimal-rights user." });
    }
    catch { /* module list not readable by the audit user */ }
    const url = p.get("web.base.url");
    if (url && !url.startsWith("https://"))
        findings.push({ id: "cfg.base_url_http", severity: "medium", title: "web.base.url is not HTTPS", detail: `Value: ${url}. Emailed links and portal URLs will use HTTP.`, fix: "Set web.base.url to the https:// address and enable proxy_mode." });
    if (p.get("auth_signup.allow_uninvited") === "True")
        findings.push({ id: "cfg.open_signup", severity: "medium", title: "Anyone can sign up (uninvited signup enabled)", detail: "auth_signup.allow_uninvited is True.", fix: "Disable free sign-up unless the website needs it." });
    const min = Number(p.get("auth_password_policy.minlength") ?? 8);
    if (min < 12)
        findings.push({ id: "cfg.password_length", severity: "low", title: `Minimum password length is ${min}`, detail: p.has("auth_password_policy.minlength") ? "Set explicitly." : "Odoo default.", fix: "Raise auth_password_policy.minlength to 12 or more." });
    if (!findings.length)
        findings.push({ id: "cfg.ok", severity: "info", title: "Readable configuration parameters look sound", detail: "master password, list_db, dbfilter and proxy_mode live in odoo.conf and cannot be read via the API; external scan covers list_db.", fix: "Review odoo.conf during the baseline audit." });
    return findings;
}
const MCP_MODULES = ["mcp_server", "ai_oca_mcp", "ai_mcp", "tv_odoo_mcp_server", "odoo_ai_mcp_server"];
const DEDUCT = { critical: 25, high: 15, medium: 7, low: 3, info: 0 };
export function scorecard(findings) {
    const score = Math.max(0, 100 - findings.reduce((s, f) => s + DEDUCT[f.severity], 0));
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
    const sorted = [...findings].filter(f => f.severity !== "info").sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    const counts = Object.fromEntries(SEVERITY_ORDER.map(s => [s, findings.filter(f => f.severity === s).length]));
    return { score, grade, counts, top_fixes: sorted.slice(0, 3) };
}
