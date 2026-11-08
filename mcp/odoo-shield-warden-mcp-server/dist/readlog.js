import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
let lastHash;
/**
 * Optional tamper-evident log of every Odoo read (SHIELD_AUDIT_LOG=<path>): JSONL, each line carries
 * the SHA-256 of the previous line's hash plus its own content. Logs model, fields and row count, never values.
 */
export function logRead(entry) {
    const path = process.env.SHIELD_AUDIT_LOG;
    if (!path)
        return;
    if (lastHash === undefined) {
        lastHash = "";
        if (existsSync(path)) {
            const lines = readFileSync(path, "utf8").trim().split("\n");
            const tail = lines[lines.length - 1];
            if (tail)
                lastHash = JSON.parse(tail).hash;
        }
    }
    const body = { ts: new Date().toISOString(), ...entry, prev: lastHash };
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    appendFileSync(path, JSON.stringify({ ...body, hash }) + "\n");
    lastHash = hash;
}
export function verifyChain(path) {
    let prev = "";
    for (const line of readFileSync(path, "utf8").trim().split("\n")) {
        const { hash, ...body } = JSON.parse(line);
        if (body.prev !== prev || createHash("sha256").update(JSON.stringify(body)).digest("hex") !== hash)
            return false;
        prev = hash;
    }
    return true;
}
