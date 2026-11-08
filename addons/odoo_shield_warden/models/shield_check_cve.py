"""Offline advisory feed check (K10): maps the running Odoo build to published security advisories.

Data comes from data/advisories.json shipped with the module, plus optional entries an administrator
adds offline in the system parameter ``shield.advisory_extra`` (JSON list, same shape). Nothing here
touches the network; refreshing the feed is a manual edit of the data file.
"""

import json
import os
from datetime import date

from odoo import _, fields, models, release

from .shield_check import listing, result

FEED_MAX_AGE_DAYS = 90
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REQUIRED_KEYS = ("id", "series", "module", "published", "severity", "url")


def _parse_date(value):
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


class ShieldCheckCve(models.AbstractModel):
    _inherit = "shield.check"

    def _advisory_feed(self):
        """Return (feed metadata, valid advisories, rejected ids). Entries lacking a source URL are rejected."""
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "advisories.json")
        with open(path, encoding="utf-8") as fh:
            feed = json.load(fh)
        entries = list(feed.get("advisories", []))
        extra = self._param("shield.advisory_extra", "")
        if extra:
            try:
                parsed = json.loads(extra)
                entries += parsed if isinstance(parsed, list) else [{}]
            except ValueError:
                entries.append({"id": "shield.advisory_extra (invalid JSON)"})
        valid, rejected = [], []
        for adv in entries:
            ok = (isinstance(adv, dict) and all(adv.get(k) for k in REQUIRED_KEYS)
                  and isinstance(adv["series"], list) and str(adv["url"]).startswith("https://")
                  and _parse_date(adv["published"]) and adv["severity"] in SEVERITY_RANK
                  and (not adv.get("fixed_build") or _parse_date(adv["fixed_build"])))
            if not ok:
                rejected.append(str(adv.get("id") or "?") if isinstance(adv, dict) else "?")
            elif not adv.get("example"):
                valid.append(adv)
        return feed, valid, rejected

    def _check_cve_feed(self):
        if "saas" in release.serie:
            return result("pass", _("Odoo Online is patched by Odoo."))
        feed, advisories, rejected = self._advisory_feed()
        build = self._build_date()
        hits = []
        for adv in advisories:
            if release.serie not in adv["series"] or not self._installed(adv["module"]):
                continue
            # fixed_build is the first build with the fix; when unknown, the publication date is the best proxy.
            fixed = _parse_date(adv.get("fixed_build") or adv["published"])
            if not build or build < fixed:
                hits.append(adv)
        if hits:
            hits.sort(key=lambda a: -SEVERITY_RANK[a["severity"]])
            worst = "critical" if hits[0]["severity"] == "critical" else "high"
            return result(
                "fail",
                _("Build %(v)s predates the fix for %(n)s known advisory(ies): %(items)s. "
                  "Update to the latest %(s)s build.", v=release.version, n=len(hits), s=release.serie,
                  items="; ".join(f"{a['id']} ({a['module']}, {a['severity']})" for a in hits)),
                "\n".join(f"{a['id']} {a['module']}: {a.get('summary', '')} Source: {a['url']}" for a in hits),
                severity=worst)
        problems = []
        updated = _parse_date(feed.get("updated"))
        if not updated or (fields.Date.context_today(self) - updated).days > FEED_MAX_AGE_DAYS:
            problems.append(_("the advisory data was last updated %s, so a clean result proves little",
                              feed.get("updated") or _("never")))
        if release.serie not in feed.get("reviewed_series", []):
            problems.append(_("the feed has not been reviewed for series %s", release.serie))
        if rejected:
            problems.append(_("%(n)s feed entry(ies) were ignored for missing fields or a source URL: %(ids)s",
                              n=len(rejected), ids=listing(rejected, limit=5)))
        if not build:
            problems.append(_("the build date of %s is unknown", release.version))
        if problems:
            return result("warn", _("No known advisory applies to build %(v)s, but %(why)s.", v=release.version,
                                    why="; ".join(problems)), severity="medium")
        return result("pass", _("No known advisory applies to build %(v)s (feed of %(u)s, %(n)s entries).",
                                v=release.version, u=feed["updated"], n=len(advisories)))
