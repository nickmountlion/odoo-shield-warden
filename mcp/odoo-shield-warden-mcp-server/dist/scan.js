import net from "node:net";
import tls from "node:tls";
const TIMEOUT_MS = 10_000;
async function get(url, signal, init = {}) {
    try {
        return await fetch(url, { redirect: "manual", ...init, signal: AbortSignal.any([signal, AbortSignal.timeout(TIMEOUT_MS)]) });
    }
    catch {
        return null;
    }
}
function tcpOpen(host, port) {
    return new Promise(resolve => {
        const socket = net.connect({ host, port, timeout: 3000 });
        socket.once("connect", () => (socket.destroy(), resolve(true)));
        socket.once("timeout", () => (socket.destroy(), resolve(false)));
        socket.once("error", () => resolve(false));
    });
}
function certInfo(host, port) {
    return new Promise(resolve => {
        const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: 5000 }, () => {
            const cert = socket.getPeerCertificate();
            const info = {
                daysLeft: Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000),
                protocol: socket.getProtocol(),
                selfSigned: !socket.authorized && /self.signed/i.test(String(socket.authorizationError))
            };
            socket.destroy();
            resolve(info);
        });
        socket.once("timeout", () => (socket.destroy(), resolve(null)));
        socket.once("error", () => resolve(null));
    });
}
/** Passive, unauthenticated checks only: GETs, one empty JSON-RPC list call, TLS handshake, TCP connect. */
export async function scanExternal(rawUrl, signal) {
    const base = new URL(rawUrl);
    const host = base.hostname;
    const findings = [];
    const add = (f) => findings.push(f);
    // Transport
    if (base.protocol === "https:") {
        const info = await certInfo(host, Number(base.port || 443));
        if (!info) {
            add({ id: "tls.handshake", severity: "high", title: "TLS handshake failed", detail: `Could not complete a TLS handshake with ${host}.`, fix: "Check the certificate and that port 443 is served by the reverse proxy." });
        }
        else {
            if (info.daysLeft < 0)
                add({ id: "tls.expired", severity: "critical", title: "TLS certificate expired", detail: `Expired ${-info.daysLeft} days ago.`, fix: "Renew the certificate now and automate renewal (certbot or the proxy's ACME support)." });
            else if (info.daysLeft < 14)
                add({ id: "tls.expiry", severity: "high", title: "TLS certificate expires within 14 days", detail: `${info.daysLeft} days left.`, fix: "Renew the certificate and confirm automatic renewal works." });
            else if (info.daysLeft < 30)
                add({ id: "tls.expiry", severity: "medium", title: "TLS certificate expires within 30 days", detail: `${info.daysLeft} days left.`, fix: "Check that automatic renewal is running." });
            if (info.selfSigned)
                add({ id: "tls.selfsigned", severity: "high", title: "Self-signed certificate", detail: "Browsers and integrations cannot verify this server.", fix: "Install a certificate from a public CA." });
            if (info.protocol && ["TLSv1", "TLSv1.1"].includes(info.protocol))
                add({ id: "tls.protocol", severity: "high", title: `Obsolete protocol ${info.protocol} negotiated`, detail: "Legacy TLS versions are insecure.", fix: "Allow only TLS 1.2 and 1.3 on the proxy." });
        }
    }
    else {
        add({ id: "tls.none", severity: "critical", title: "Odoo is served over plain HTTP", detail: `${base.origin} does not use HTTPS, so logins and data travel unencrypted.`, fix: "Terminate TLS at a reverse proxy and redirect all HTTP to HTTPS." });
    }
    if (base.protocol === "https:") {
        const http = new URL(base.href);
        http.protocol = "http:";
        http.port = "";
        const res = await get(http, signal);
        const location = res?.headers.get("location") ?? "";
        if (res && !(res.status >= 300 && res.status < 400 && location.startsWith("https://"))) {
            add({ id: "tls.redirect", severity: "medium", title: "HTTP does not redirect to HTTPS", detail: `GET ${http.origin} returned HTTP ${res.status}.`, fix: "Redirect port 80 to HTTPS at the proxy." });
        }
    }
    // Headers on the login page
    const login = await get(new URL("/web/login", base), signal);
    if (!login) {
        add({ id: "http.unreachable", severity: "high", title: "Login page unreachable", detail: `GET ${new URL("/web/login", base).href} did not answer.`, fix: "Confirm the URL and that the instance is up." });
    }
    else {
        const h = (name) => login.headers.get(name);
        if (base.protocol === "https:" && !h("strict-transport-security"))
            add({ id: "hdr.hsts", severity: "medium", title: "Missing HSTS header", detail: "Strict-Transport-Security is not set.", fix: "Add 'Strict-Transport-Security: max-age=31536000' at the proxy." });
        if (!h("x-content-type-options"))
            add({ id: "hdr.nosniff", severity: "low", title: "Missing X-Content-Type-Options", detail: "The 'nosniff' header is not set.", fix: "Add 'X-Content-Type-Options: nosniff'." });
        if (!h("x-frame-options") && !(h("content-security-policy") ?? "").includes("frame-ancestors"))
            add({ id: "hdr.framing", severity: "low", title: "Clickjacking protection missing", detail: "Neither X-Frame-Options nor CSP frame-ancestors is set.", fix: "Add 'X-Frame-Options: SAMEORIGIN' unless embedding is intended." });
        if (!h("referrer-policy"))
            add({ id: "hdr.referrer", severity: "low", title: "Missing Referrer-Policy", detail: "Referrer-Policy is not set.", fix: "Add 'Referrer-Policy: strict-origin-when-cross-origin'." });
        const server = h("server");
        if (server && /\d/.test(server))
            add({ id: "hdr.server", severity: "low", title: "Server header discloses a version", detail: `Server: ${server}`, fix: "Hide the version (e.g. 'server_tokens off' in nginx)." });
    }
    // Database manager exposure
    const list = await get(new URL("/web/database/list", base), signal, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "call", params: {}, id: 1 })
    });
    let listBody = null;
    try {
        listBody = list ? (await list.json()) : null;
    }
    catch { /* not JSON */ }
    if (Array.isArray(listBody?.result)) {
        add({ id: "odoo.list_db", severity: "high", title: "Database list is public (list_db enabled)", detail: `Anyone can list databases: ${listBody.result.slice(0, 5).join(", ")}.`, fix: "Set list_db = False and a strict dbfilter in odoo.conf." });
    }
    const manager = await get(new URL("/web/database/manager", base), signal);
    if (manager?.status === 200) {
        add({ id: "odoo.db_manager", severity: "critical", title: "Database manager is exposed", detail: "/web/database/manager answers publicly, allowing backup, restore and drop with the master password.", fix: "Set list_db = False, block /web/database/* at the proxy, and use a long random admin_passwd." });
    }
    // Version disclosure
    const version = await get(new URL("/web/webclient/version_info", base), signal, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "call", params: {}, id: 1 })
    });
    try {
        const vb = version ? (await version.json()) : null;
        if (vb?.result?.server_version)
            add({ id: "odoo.version", severity: "info", title: `Odoo version is public: ${vb.result.server_version}`, detail: "Version info is available without login (normal for Odoo; used to plan upgrades).", fix: "Optional: block /web/webclient/version_info at the proxy." });
    }
    catch { /* not JSON */ }
    // Direct service ports
    for (const [port, label, sev] of [[5432, "PostgreSQL", "critical"], [8069, "Odoo HTTP (bypasses proxy)", "high"], [8072, "Odoo longpolling/websocket (bypasses proxy)", "medium"]]) {
        if (await tcpOpen(host, port)) {
            add({ id: `port.${port}`, severity: sev, title: `Port ${port} reachable from outside: ${label}`, detail: `${host}:${port} accepts TCP connections.`, fix: `Firewall port ${port}; expose only 80/443 through the reverse proxy.` });
        }
    }
    return findings;
}
