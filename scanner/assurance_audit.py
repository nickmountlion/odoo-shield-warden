"""Odoo Assurance - full assessment of a self-hosted (docker compose) Odoo.

Combines the read-only Shield audit (shield_audit.py) with host-level checks
that need operator access: Odoo config baseline, PostgreSQL health, patching,
and an actual backup-restore verification into a scratch database.
Each finding is tagged with the subscription concept it belongs to.

Usage (on the docker host):
    python3 assurance_audit.py --compose-dir ~/odoo --url http://localhost:8069 \
        --db odoo-shield-warden --user admin --password admin --out report
"""

import argparse
import configparser
import datetime as dt
import hashlib
import json
import subprocess
import time
from pathlib import Path

from shield_audit import Audit, SEVERITY_WEIGHT, grade, render_html

FILESTORE = "/var/lib/odoo/.local/share/Odoo/filestore"
CONCEPT = {
    "external": "Shield", "config": "Shield", "access": "Shield", "backup": "Shield",
    "health": "Care", "database": "Care", "patching": "Care",
    "integration": "Integration Watch", "upgrade": "Upgrade Runway", "audit": "Audit",
}
# Odoo supports the latest three major versions; update when a new one ships.
SUPPORTED_SERIES = ["17.0", "18.0", "19.0"]
LATEST_SERIES = "19.0"
WEAK_MASTER = {"admin", "odoo", "password", "123456", ""}


class HostAudit(Audit):
    def __init__(self, compose_dir, **kw):
        super().__init__(**kw)
        self.compose_dir = Path(compose_dir).expanduser()

    def sh(self, *args, input_bytes=None, check=True):
        res = subprocess.run(["docker", "compose", *args], cwd=self.compose_dir,
                             input=input_bytes, capture_output=True, timeout=900)
        if check and res.returncode:
            raise RuntimeError(res.stderr.decode(errors="replace")[-300:])
        return res.stdout

    def psql(self, sql, db=None):
        out = self.sh("exec", "-T", "db", "psql", "-U", "odoo", "-d", db or self.db, "-tA", "-F", "\t", "-c", sql)
        return [line.split("\t") for line in out.decode().splitlines() if line]

    # -- Shield: config baseline (needs odoo.conf) --------------------------

    def check_odoo_conf(self):
        cp = configparser.ConfigParser()
        cp.read(self.compose_dir / "config" / "odoo.conf")
        o = cp["options"] if cp.has_section("options") else {}
        self.facts["odoo_conf"] = {k: ("***" if "pass" in k else v) for k, v in o.items()}
        if o.get("admin_passwd", "") in WEAK_MASTER:
            self.add("cfg.master_password", "critical", "Weak database master password",
                     "admin_passwd is a default/guessable value and stored in plain text.",
                     "Set a long random admin_passwd (Odoo will hash it) and keep it in the password manager.",
                     "config")
        if o.get("list_db", "True").lower() != "false":
            self.add("cfg.list_db", "medium", "list_db not disabled in odoo.conf",
                     "list_db is unset or True.", "Set list_db = False.", "config")
        if not o.get("dbfilter"):
            self.add("cfg.dbfilter", "low", "No dbfilter configured",
                     "Any database on the server can be selected by hostname/URL.",
                     "Set dbfilter = ^%d$ or the explicit database name.", "config")
        if o.get("proxy_mode", "False").lower() != "true":
            self.add("cfg.proxy_mode", "low", "proxy_mode disabled",
                     "Needed for correct client IPs and HTTPS URLs behind a reverse proxy.",
                     "Enable proxy_mode once Odoo sits behind the TLS proxy.", "config")
        # dev_mode is only honoured as a CLI flag (--dev); a dev_mode key in odoo.conf is ignored,
        # so it is checked from inside Odoo by the odoo_shield_warden module instead.
        if int(o.get("workers", "0") or 0) == 0:
            self.add("health.workers", "medium", "Odoo running in single-process threaded mode",
                     "workers = 0: no request isolation, no memory/time limits, no gevent longpolling.",
                     "Set workers = (2 x CPU) + 1 with limit_memory_* and limit_time_* tuned.", "health")
        if not o.get("data_dir"):
            self.add("cfg.data_dir", "low", "data_dir not set explicitly",
                     f"Filestore lives at the implicit default {FILESTORE}; easy to miss in backups.",
                     "Set data_dir = /var/lib/odoo so backup scope is explicit.", "config")

    # -- Shield: backup restore verification --------------------------------

    def check_backups(self):
        cfg = (self.compose_dir / "docker-compose.yml").read_text()
        has_job = any(w in cfg for w in ("backup", "restic", "borg", "pgbackrest"))
        if not has_job and not list(self.compose_dir.glob("backups/*")):
            self.add("bkp.none", "critical", "No backups configured",
                     "No backup service, schedule or backup files found for database or filestore.",
                     "Schedule nightly pg_dump + filestore archive to off-host storage (restic/borg), "
                     "with retention and monthly restore tests.", "backup")

    def check_restore(self):
        scratch = f"{self.db}_restore_test"
        start = time.monotonic()
        dump = self.sh("exec", "-T", "db", "pg_dump", "-U", "odoo", "-Fc", self.db)
        self.psql(f'DROP DATABASE IF EXISTS "{scratch}"', db="postgres")
        self.psql(f'CREATE DATABASE "{scratch}" OWNER odoo', db="postgres")
        self.sh("exec", "-T", "db", "pg_restore", "-U", "odoo", "-d", scratch, "--no-owner", input_bytes=dump)
        src_fs = self.sh("exec", "-T", "odoo", "tar", "-C", f"{FILESTORE}/{self.db}", "-cf", "-", ".")
        self.sh("exec", "-T", "odoo", "bash", "-c",
                f"rm -rf {FILESTORE}/{scratch} && mkdir -p {FILESTORE}/{scratch} && tar -C {FILESTORE}/{scratch} -xf -",
                input_bytes=src_fs)
        rto = time.monotonic() - start

        count_sql = ("SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY relname")
        tables = [r[0] for r in self.psql(count_sql)]
        mismatches = []
        for chunk in (tables[i:i + 200] for i in range(0, len(tables), 200)):
            union = " UNION ALL ".join(f"SELECT '{t}', count(*) FROM \"{t}\"" for t in chunk)
            a = dict(map(tuple, self.psql(union)))
            b = dict(map(tuple, self.psql(union, db=scratch)))
            mismatches += [f"{t}: {a[t]} vs {b.get(t)}" for t in chunk if a[t] != b.get(t)]
        fs_sum = lambda d: self.sh("exec", "-T", "odoo", "bash", "-c",
                                   f"cd {FILESTORE}/{d} && find . -type f -print0 | sort -z | xargs -0 -r sha256sum | sha256sum").decode().split()[0]
        fs_ok = fs_sum(self.db) == fs_sum(scratch)

        self.facts["restore_test"] = {
            "dump_mb": round(len(dump) / 1e6, 2), "tables_compared": len(tables),
            "row_mismatches": len(mismatches), "filestore_checksum_match": fs_ok,
            "measured_rto_seconds": round(rto, 1),
        }
        self.sh("exec", "-T", "odoo", "rm", "-rf", f"{FILESTORE}/{scratch}")
        self.psql(f'DROP DATABASE IF EXISTS "{scratch}"', db="postgres")
        if mismatches or not fs_ok:
            self.add("bkp.restore_failed", "critical", "Restore verification failed",
                     f"{len(mismatches)} table(s) differ; filestore match: {fs_ok}. " + "; ".join(mismatches[:5]),
                     "Investigate dump consistency before relying on these backups.", "backup")
        else:
            self.add("bkp.restore_ok", "info", "Restore drill passed",
                     f"Dump of {len(dump) / 1e6:.1f} MB restored into a scratch DB in {rto:.0f}s; "
                     f"{len(tables)} tables match row-for-row and filestore checksums match. "
                     "This proves a dump can be restored, not that scheduled backups exist.",
                     "Repeat monthly against the real off-host backup copy.", "backup")

    # -- Care: PostgreSQL health -------------------------------------------

    def check_postgres(self):
        (version,), = self.psql("SHOW server_version")
        (size,), = self.psql(f"SELECT pg_size_pretty(pg_database_size('{self.db}'))")
        (max_conn,), = self.psql("SHOW max_connections")
        (conns,), = self.psql("SELECT count(*) FROM pg_stat_activity")
        (autovac,), = self.psql("SHOW autovacuum")
        (hit,), = self.psql("SELECT round(100.0*sum(blks_hit)/nullif(sum(blks_hit+blks_read),0),1) FROM pg_stat_database")
        (shared,), = self.psql("SHOW shared_buffers")
        pss = self.psql("SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements'")
        bloat = self.psql("SELECT relname, n_dead_tup, n_live_tup FROM pg_stat_user_tables "
                          "WHERE n_dead_tup > 1000 AND n_dead_tup > n_live_tup * 0.2 ORDER BY n_dead_tup DESC LIMIT 5")
        self.facts["postgres"] = {"version": version, "db_size": size, "connections": f"{conns}/{max_conn}",
                                  "cache_hit_pct": hit, "shared_buffers": shared, "autovacuum": autovac}
        if not pss:
            self.add("db.no_pss", "low", "pg_stat_statements not enabled",
                     "Slow-query analysis is not possible.",
                     "Add shared_preload_libraries=pg_stat_statements and CREATE EXTENSION.", "database")
        if autovac != "on":
            self.add("db.autovacuum_off", "high", "Autovacuum disabled", "autovacuum = off.",
                     "Turn autovacuum on.", "database")
        if shared in ("128MB",):
            self.add("db.untuned", "low", "PostgreSQL running default memory settings",
                     f"shared_buffers = {shared} (container default).",
                     "Tune with pgTune for the host RAM (typically ~25% of RAM).", "database")
        if int(conns) > int(max_conn) * 0.8:
            self.add("db.connections", "high", "Connection pool near limit", f"{conns}/{max_conn} in use.",
                     "Raise max_connections or lower db_maxconn x workers.", "database")
        if bloat:
            self.add("db.bloat", "medium", "Tables with high dead-tuple ratio",
                     ", ".join(f"{r[0]} ({r[1]} dead)" for r in bloat), "VACUUM ANALYZE and review autovacuum.",
                     "database")

    # -- Care: patching ------------------------------------------------------

    def check_patching(self):
        images = json.loads(self.sh("images", "--format", "json") or b"[]")
        cfg = (self.compose_dir / "docker-compose.yml").read_text()
        floating = [i for i in ("odoo:18.0", "postgres:16") if i in cfg]
        ages = {}
        for img in {f"{i.get('Repository')}:{i.get('Tag')}" for i in images}:
            out = subprocess.run(["docker", "image", "inspect", img, "--format", "{{.Created}}"],
                                 capture_output=True, text=True).stdout.strip()
            if out:
                created = dt.datetime.fromisoformat(out[:19])
                ages[img] = (dt.datetime.now() - created).days
        self.facts["image_age_days"] = ages
        stale = {k: v for k, v in ages.items() if v > 30}
        if stale:
            self.add("patch.stale_images", "medium", "Container images older than 30 days",
                     ", ".join(f"{k} ({v}d)" for k, v in stale.items()),
                     "Pull and redeploy in a staging-first patch window.", "patching")
        if floating:
            self.add("patch.floating_tags", "low", "Images pinned to floating tags",
                     ", ".join(floating) + " change silently on pull; no record of what is deployed.",
                     "Pin image digests and bump them deliberately in the patch window.", "patching")
        self.add("patch.no_staging", "medium", "No staging environment",
                 "Patches and upgrades would go straight to this instance.",
                 "Stand up a staging stack refreshed monthly from production (anonymized).", "patching")

    # -- Upgrade Runway / Integration Watch ---------------------------------

    def check_upgrade(self):
        serie = self.facts.get("server_serie") or ""
        if serie and serie not in SUPPORTED_SERIES:
            self.add("upg.unsupported", "critical", f"Odoo {serie} is out of support", "No security fixes.",
                     "Plan the migration now.", "upgrade")
        elif serie and serie != LATEST_SERIES:
            self.add("upg.behind", "low", f"One major version behind ({serie} vs {LATEST_SERIES})",
                     f"{serie} is supported, but drops out of support once two newer releases exist.",
                     f"Scan custom modules against {LATEST_SERIES} and schedule a staging dry-run.", "upgrade")

    def check_integrations(self):
        webhooks = self.call("ir.actions.server", "search_count", [("state", "=", "webhook")])
        providers = self.call("ir.module.module", "search_read",
                              [("state", "=", "installed"), ("name", "=like", "payment_%")], fields=["name"]) \
            if self.installed("payment") else []
        self.facts["integrations"] = {"outgoing_webhooks": webhooks, "payment_modules": [p["name"] for p in providers]}
        if not webhooks and not providers:
            self.add("int.none", "info", "No integrations to monitor",
                     "No outgoing webhooks or payment providers installed; Integration Watch not applicable yet.",
                     "Re-check when e-commerce, payments or 3PL connectors are added.", "integration")

    def run(self):
        report = super().run()
        for name in ("odoo_conf", "backups", "restore", "postgres", "patching", "upgrade", "integrations"):
            self.safe(getattr(self, f"check_{name}"), name)
        # odoo.conf check supersedes the external list_db finding
        if any(f["id"] == "ext.list_db" for f in self.findings):
            self.findings = [f for f in self.findings if f["id"] != "cfg.list_db"]
        for f in self.findings:
            f["concept"] = CONCEPT.get(f["category"], "Audit")
        order = list(SEVERITY_WEIGHT)
        self.findings.sort(key=lambda f: order.index(f["severity"]))
        score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in self.findings))
        concepts = {}
        for f in self.findings:
            c = concepts.setdefault(f["concept"], {"findings": 0, "penalty": 0})
            c["findings"] += 1
            c["penalty"] += SEVERITY_WEIGHT[f["severity"]]
        report.update(score=score, grade=grade(score), findings=self.findings, facts=self.facts,
                      concepts={k: {**v, "score": max(0, 100 - v["penalty"])} for k, v in concepts.items()},
                      top_fixes=[f for f in self.findings if f["severity"] != "info"][:3])
        return report


def main():
    p = argparse.ArgumentParser(description="Odoo Assurance full assessment")
    p.add_argument("--compose-dir", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--out", default="report")
    a = p.parse_args()

    report = HostAudit(a.compose_dir, url=a.url, db=a.db, user=a.user, password=a.password).run()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    html = render_html(report).replace("Odoo Shield — Baseline Scorecard", "Odoo Assurance — Baseline Assessment")
    concept_rows = "".join(f"<tr><td>{k}</td><td>{v['score']}/100</td><td>{v['findings']}</td></tr>"
                           for k, v in sorted(report["concepts"].items()))
    html = html.replace("<h2>Top 3 fixes</h2>", "<h2>By service</h2><table><tr><th>Concept</th><th>Score</th>"
                        f"<th>Findings</th></tr>{concept_rows}</table><h2>Top 3 fixes</h2>")
    out.with_suffix(".html").write_text(html, encoding="utf-8")

    print(f"Score {report['score']}/100 (grade {report['grade']}) - {len(report['findings'])} findings")
    for k, v in sorted(report["concepts"].items()):
        print(f"  {k:<18} {v['score']:>3}/100  ({v['findings']} findings)")
    for f in report["findings"]:
        print(f"  [{f['severity']:>8}] {f['concept']:<17} {f['title']}")
    print(json.dumps(report["facts"].get("restore_test"), indent=None))
    print(f"Wrote {out.with_suffix('.json')} and {out.with_suffix('.html')}")


if __name__ == "__main__":
    main()
