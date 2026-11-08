import * as z from "zod/v4";
import { logRead } from "./readlog.js";

const ClientSchema = z.object({
  url: z.url(),
  db: z.string().min(1),
  login: z.string().min(1),
  apiKey: z.string().min(1)
});
export type ClientConfig = z.infer<typeof ClientSchema>;

/** Per-client credentials come from SHIELD_CLIENTS (JSON), never from tool arguments. */
export function loadClients(): Record<string, ClientConfig> {
  const raw = process.env.SHIELD_CLIENTS;
  if (!raw) return {};
  return z.record(z.string(), ClientSchema).parse(JSON.parse(raw));
}

export function getClient(id: string): ClientConfig {
  const clients = loadClients();
  const client = clients[id];
  if (!client) {
    const known = Object.keys(clients);
    throw new Error(
      known.length
        ? `Unknown client '${id}'. Configured clients: ${known.join(", ")}. Use shield_list_clients to list them.`
        : "No clients configured. Set SHIELD_CLIENTS to JSON like {\"acme\":{\"url\":\"https://erp.acme.com\",\"db\":\"acme\",\"login\":\"audit@acme.com\",\"apiKey\":\"...\"}}."
    );
  }
  return client;
}

/** Only these models can ever be read; anything else is refused before a request is sent. */
export const ALLOWED_MODELS = new Set(["res.users", "res.users.apikeys", "res.groups", "ir.model.data", "ir.config_parameter", "ir.module.module"]);

type Domain =(string | number | boolean | string[] | unknown[])[][];
type Row = Record<string, unknown>;

/**
 * Read-only Odoo client. Exposes only search_read and fields_get, so no tool can write.
 * Tries the classic /jsonrpc endpoint and falls back to /json/2 (Odoo 19+) when /jsonrpc is gone.
 */
export class OdooReadOnly {
  private uid?: number;
  private mode?: "jsonrpc" | "json2";

  constructor(private readonly c: ClientConfig, private readonly signal: AbortSignal) {}

  private async post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown }> {
    let response: Response;
    try {
      response = await fetch(new URL(path, this.c.url), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.any([this.signal, AbortSignal.timeout(30_000)])
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "TimeoutError") {
        throw new Error(`${this.c.url} did not respond within 30 seconds. Check the URL and that the instance is reachable.`);
      }
      throw new Error(`Cannot reach ${this.c.url}: ${(error as Error).message}. Check the URL and network access (VPN/WireGuard).`);
    }
    let json: unknown = null;
    try {
      json = await response.json();
    } catch {
      /* non-JSON body */
    }
    return { status: response.status, json };
  }

  private async jsonrpc(service: string, method: string, args: unknown[]): Promise<unknown> {
    const { status, json } = await this.post("/jsonrpc", { jsonrpc: "2.0", method: "call", params: { service, method, args }, id: 1 });
    if (status === 404) throw new NotFound();
    const body = json as { result?: unknown; error?: { data?: { message?: string }; message?: string } } | null;
    if (body?.error) throw new Error(body.error.data?.message ?? body.error.message ?? "Odoo returned an error");
    if (!body) throw new Error(`Odoo returned HTTP ${status} without JSON.`);
    return body.result;
  }

  private async detect(): Promise<void> {
    if (this.mode) return;
    try {
      const uid = await this.jsonrpc("common", "authenticate", [this.c.db, this.c.login, this.c.apiKey, {}]);
      if (!uid) throw new Error(`Odoo rejected the login/API key for database '${this.c.db}'. Check the credentials in SHIELD_CLIENTS.`);
      this.uid = uid as number;
      this.mode = "jsonrpc";
    } catch (error) {
      if (!(error instanceof NotFound)) throw error;
      this.mode = "json2";
    }
  }

  private guard(model: string): void {
    if (!ALLOWED_MODELS.has(model)) {
      throw new Error(`Model '${model}' is not on Shield's read allowlist (${[...ALLOWED_MODELS].join(", ")}).`);
    }
  }

  async searchRead(model: string, domain: Domain, fields: string[]): Promise<Row[]> {
    this.guard(model);
    await this.detect();
    const rows =
      this.mode === "jsonrpc"
        ? ((await this.jsonrpc("object", "execute_kw", [this.c.db, this.uid, this.c.apiKey, model, "search_read", [domain], { fields }])) as Row[])
        : ((await this.json2(model, "search_read", { domain, fields })) as Row[]);
    logRead({ client: this.c.db, model, fields, rows: rows.length });
    return rows;
  }

  async fieldNames(model: string): Promise<Set<string>> {
    this.guard(model);
    await this.detect();
    const result =
      this.mode === "jsonrpc"
        ? await this.jsonrpc("object", "execute_kw", [this.c.db, this.uid, this.c.apiKey, model, "fields_get", [], { attributes: ["type"] }])
        : await this.json2(model, "fields_get", { attributes: ["type"] });
    return new Set(Object.keys(result as Record<string, unknown>));
  }

  private async json2(model: string, method: string, body: Record<string, unknown>): Promise<unknown> {
    const { status, json } = await this.post(`/json/2/${model}/${method}`, body, {
      Authorization: `bearer ${this.c.apiKey}`,
      "X-Odoo-Database": this.c.db
    });
    if (status === 401) throw new Error("Odoo rejected the API key (HTTP 401). Check the credentials in SHIELD_CLIENTS.");
    if (status === 403) throw new Error(`Access denied reading ${model} (HTTP 403). The audit user needs read access; ${model} is admin-only.`);
    if (status >= 400) throw new Error(`Odoo returned HTTP ${status} for ${model}.${method}.`);
    return json;
  }
}

class NotFound extends Error {}
