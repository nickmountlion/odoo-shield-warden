"""The Kaizen loop: one command that tests, attacks and grades Odoo Shield Warden, and fails on any regression.

    python lab/kaizen_loop.py            # full loop on a fresh lab database
    python lab/kaizen_loop.py --keep-db  # reuse the existing lab database (faster, less strict)

Steps
  1. Unit tests in a throwaway database (install from scratch, all tests).
  2. A brand-new lab database (ODOO_SHIELD_WARDEN_DB, default "odoo_shield_warden_lab") with Accounting and Shield.
  3. Seed the fraud demo, then attack waves 1-4, assessing after each wave.
  4. Compare with lab/results/best.json: any scenario detected or prevented before but not now is a regression
     (exit code 1). A run with no regression and at least as much coverage becomes the new best.

Runs against the local docker compose stack only (ODOO_COMPOSE_DIR, default ~/odoo in WSL "Ubuntu").
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "lab" / "results"
LAB_DB = os.environ.get("ODOO_SHIELD_WARDEN_DB", "odoo_shield_warden_lab")
COMPOSE_DIR = os.environ.get("ODOO_COMPOSE_DIR", "~/odoo")
ODOO = ("docker compose exec -T odoo odoo -c /etc/odoo/odoo.conf --stop-after-init --http-port=8090 "
        "--db_host=db --db_user=odoo --db_password=odoo --without-demo=all")


def stack(cmd, timeout=1800):
    """Run a shell command next to the docker compose stack (WSL on Windows, directly elsewhere)."""
    full = f"cd {COMPOSE_DIR} && {{ {cmd} ; }} < /dev/null"  # docker exec must not read our stdin
    argv = ["wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc", full] if os.name == "nt" else ["bash", "-lc", full]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def drop(db):
    """Drop a database even while the running Odoo server holds connections to it, and prove it is gone."""
    stack(f"docker compose exec -T db psql -U odoo -d postgres -c 'DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)' && "
          f"docker compose exec -T odoo rm -rf /var/lib/odoo/.local/share/Odoo/filestore/{db}")
    left = stack(f"docker compose exec -T db psql -U odoo -d postgres -tAc "
                 f"\"SELECT count(*) FROM pg_database WHERE datname = '{db}'\"")
    if left.stdout.strip() != "0":
        raise SystemExit(f"Could not drop database {db}: the run would not be fresh. ({left.stdout.strip()!r})")


def step(title):
    print(f"\n== {title}")


def run_tests(title="1. Unit tests (fresh install)", db="shield_kaizen_test", modules="account,odoo_shield_warden",
              tags="/odoo_shield_warden,/odoo_shield_warden_finance"):
    step(title)
    drop(db)
    out = stack(f"{ODOO} -d {db} -i {modules} --test-enable "
                f"--test-tags {tags} 2>&1 | grep -E 'tests.result|ERROR'")
    drop(db)
    match = re.search(r"(\d+) failed, (\d+) error\(s\) of (\d+) tests", out.stdout)
    if not match:
        print(out.stdout[-2000:] or out.stderr[-2000:])
        return {"ok": False, "summary": "test run did not report a result"}
    failed, errors, total = map(int, match.groups())
    print(f"   {total} tests, {failed} failed, {errors} errors")
    return {"ok": failed == 0 and errors == 0, "total": total, "failed": failed, "errors": errors}


def run_argentina_tests():
    """Argentine localisation: CBU accounts and withholding payments must reach the payment hold."""
    return run_tests("1b. Argentina (l10n_ar_withholding) tests", "shield_kaizen_test_ar",
                     "account,l10n_ar_withholding,odoo_shield_warden", "/odoo_shield_warden_finance:TestArgentina")


def fresh_lab():
    step(f"2. Fresh lab database '{LAB_DB}'")
    drop(LAB_DB)
    out = stack(f"{ODOO} -d {LAB_DB} -i account,odoo_shield_warden 2>&1 | grep -cE ' ERROR | CRITICAL '")
    errors = int((out.stdout or "0").strip() or 0)
    print(f"   installed; {errors} error line(s) during install")
    return errors == 0


def python(script, *args):
    env = dict(os.environ, ODOO_SHIELD_WARDEN_DB=LAB_DB, PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, str(ROOT / script), *args], capture_output=True, text=True, env=env,
                          timeout=1800)
    if proc.returncode:
        print(proc.stdout[-1500:], proc.stderr[-3000:])
        raise SystemExit(f"{script} {' '.join(args)} failed")
    return proc.stdout


def attack():
    step("3. Seed and attack waves 1-4")
    python("tools/seed_fraud_demo.py")
    for wave in (1, 2, 3, 4):
        out = python("lab/attack_lab.py", "--wave", str(wave), "--label", f"kaizen-w{wave}")
        print("   " + next(line for line in out.splitlines() if line.startswith("Coverage")))
    coverage = json.loads((RESULTS / "coverage-kaizen-w4.json").read_text(encoding="utf-8"))
    # Each wave runs in its own process: prevention results must be merged across all waves.
    coverage["prevention"] = {}
    for wave in (1, 2, 3, 4):
        wave_file = json.loads((RESULTS / f"coverage-kaizen-w{wave}.json").read_text(encoding="utf-8"))
        coverage["prevention"].update(wave_file.get("prevention") or {})
    return coverage


def grade(tests, install_ok, coverage):
    step("4. Grade against the best previous run")
    detected = {s["scenario"] for s in coverage["scenarios"] if s["detected"]}
    prevented = {name for name, ok in coverage.get("prevention", {}).items() if ok}
    best_path = RESULTS / "best.json"
    best = json.loads(best_path.read_text(encoding="utf-8")) if best_path.exists() else {"detected": [], "prevented": []}
    regressions = sorted(set(best["detected"]) - detected) + sorted(set(best["prevented"]) - prevented)
    report = {
        "when": datetime.now().isoformat(timespec="seconds"), "tests": tests, "install_ok": install_ok,
        "detected": sorted(detected), "missed": sorted(s["scenario"] for s in coverage["scenarios"] if not s["detected"]),
        "prevented": sorted(prevented), "money_at_risk": coverage.get("money_at_risk"),
        "cases": coverage.get("cases"), "alerts": coverage.get("alerts"), "regressions": regressions,
    }
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (RESULTS / f"kaizen-{stamp}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"   detected {len(detected)}/{len(coverage['scenarios'])}, prevented {len(prevented)}, "
          f"{coverage.get('cases')} case(s) from {coverage.get('alerts')} alert(s), "
          f"money at risk {coverage.get('money_at_risk'):,.2f}")
    for name in report["missed"]:
        print(f"   MISSED     {name}")
    for name in regressions:
        print(f"   REGRESSION {name}")
    passed = tests["ok"] and install_ok and not regressions
    if passed and len(detected) >= len(best["detected"]) and len(prevented) >= len(best["prevented"]):
        best_path.write_text(json.dumps({"detected": sorted(detected), "prevented": sorted(prevented),
                                         "when": report["when"]}, indent=2), encoding="utf-8")
        print("   new best recorded")
    print("\nKAIZEN LOOP:", "PASS" if passed else "FAIL")
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep-db", action="store_true", help="skip rebuilding the lab database")
    args = parser.parse_args()
    RESULTS.mkdir(exist_ok=True)
    tests = run_tests()
    ar = run_argentina_tests()
    tests["ok"] = tests["ok"] and ar["ok"]
    tests["argentina"] = ar
    install_ok = True if args.keep_db else fresh_lab()
    coverage = attack()
    sys.exit(0 if grade(tests, install_ok, coverage) else 1)


if __name__ == "__main__":
    main()
