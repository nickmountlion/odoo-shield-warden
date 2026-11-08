from unittest.mock import patch

from odoo import fields
from odoo.tests import TransactionCase, new_test_user, tagged
from odoo.tools import config


@tagged("post_install", "-at_install")
class TestThreatChecks(TransactionCase):
    """One test per real-world scenario from the attack lab (docs/REAL_WORLD_ASSESSMENT.md)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.check = cls.env["shield.check"]
        cls.clerk = new_test_user(cls.env, login="threat_clerk", groups="base.group_user")

    def test_static_scanner_patterns(self):
        hits = {label for label, _sev, _ln in self.check._scan_source(
            "from odoo import http\n"
            "@http.route('/x', auth='public', csrf=False)\n"
            "def x(self, q):\n"
            "    request.env['res.partner'].sudo()\n"
            "    request.env.cr.execute(\"SELECT 1 WHERE name = '%s'\" % q)\n"
            "    return eval(q)\n"
            "    # eval(q) in a comment is ignored\n", "controllers.py")}
        self.assertIn("SQL built from strings", hits)
        self.assertIn("eval/exec on dynamic input", hits)
        self.assertIn("CSRF protection disabled", hits)
        self.assertIn("public route combined with sudo()", hits)
        self.assertEqual(self.check._scan_source("self.env.cr.execute(query, (value,))\n", "safe.py"), [])
        self.assertEqual([h[0] for h in self.check._scan_source('<t t-raw="html"/>', "view.xml")],
                         ["raw HTML output (t-raw)"])

    def test_db_code_backdoor(self):
        self.assertEqual(self.check._check_db_code_objects()["status"], "pass")
        self.env["ir.actions.server"].create({
            "name": "Nightly sync", "model_id": self.env.ref("base.model_res_partner").id, "state": "code",
            "code": "env['res.partner.bank'].sudo().search([]).write({'acc_number': 'X'})"})
        res = self.check._check_db_code_objects()
        self.assertEqual(res["status"], "fail")
        self.assertIn("Nightly sync", res["detail"])
        self.assertIn("bank data", res["detail"])

    def test_hand_made_record_rule_on_sensitive_model(self):
        self.env["ir.rule"].create({
            "name": "Hide some users", "model_id": self.env.ref("base.model_res_users").id,
            "groups": [(6, 0, self.env.ref("base.group_user").ids)], "domain_force": "[('id', '!=', 2)]"})
        res = self.check._check_custom_record_rules()
        self.assertEqual(res["status"], "fail")
        self.assertIn("Hide some users", res["detail"])

    def test_privilege_drift_against_baseline(self):
        self.env["shield.assessment"]._run()  # baseline snapshot
        self.clerk.groups_id |= self.env.ref("base.group_system")
        res = self.check._check_privilege_drift()
        self.assertEqual(res["status"], "fail")
        self.assertIn("threat_clerk", res["detail"])

    def test_login_throttling(self):
        params = self.env["ir.config_parameter"]
        params.set_param("base.login_cooldown_after", 0)
        self.assertEqual(self.check._check_login_throttling()["status"], "fail")
        params.set_param("base.login_cooldown_after", 5)
        params.set_param("base.login_cooldown_duration", 60)
        self.assertEqual(self.check._check_login_throttling()["status"], "pass")

    def test_template_editor_outside_admins(self):
        self.clerk.groups_id |= self.env.ref("mail.group_mail_template_editor")
        res = self.check._check_template_editors()
        self.assertEqual(res["status"], "fail")
        self.assertIn("threat_clerk", res["detail"])

    def test_weak_database_credentials(self):
        with patch.dict(config.options, {"db_user": "odoo", "db_password": "odoo", "db_host": "db"}):
            self.assertEqual(self.check._check_db_credentials()["status"], "fail")
        with patch.dict(config.options, {"db_user": "odoo_app", "db_password": "x7#Kq!9vLm2$Rt", "db_host": "db"}):
            self.assertEqual(self.check._check_db_credentials()["status"], "pass")

    def test_mass_export_is_logged_and_flagged(self):
        self.env["ir.config_parameter"].set_param("shield.mass_export_rows", 20)
        self.clerk.groups_id |= self.env.ref("base.group_allow_export")
        partners = self.env["res.partner"].create([{"name": f"Lead {i}", "email": f"l{i}@x.com"} for i in range(25)])
        partners.with_user(self.clerk).export_data(["name", "email"])
        log = self.env["shield.export.log"].search([("user_id", "=", self.clerk.id)])
        self.assertEqual(log.record_count, 25)
        res = self.check._check_mass_export()
        self.assertEqual(res["status"], "fail")
        self.assertIn("threat_clerk", res["detail"])

    # -- cycle 3 -----------------------------------------------------------------------------------

    def test_patch_level_matches_advisories_and_build_age(self):
        from odoo import release
        with patch.object(release, "version", "17.0-20240601"), patch.object(release, "serie", "17.0"):
            res = self.check._check_patch_level()
        self.assertEqual(res["status"], "fail")
        self.assertIn("CVE-2024-36259", res["detail"])
        with patch.object(release, "version", "18.0-20200101"), patch.object(release, "serie", "18.0"):
            self.assertIn("days old", self.check._check_patch_level()["detail"])

    def test_cve_feed(self):
        from odoo import release
        today = fields.Date.context_today(self.check)
        with patch.object(release, "version", "17.0-20240601"), patch.object(release, "serie", "17.0"):
            res = self.check._check_cve_feed()
        self.assertEqual(res["status"], "fail")
        self.assertIn("CVE-2024-36259", res["detail"])
        self.assertIn("https://nvd.nist.gov", res["evidence"])
        stamp = today.strftime("%Y%m%d")
        with patch.object(release, "version", f"18.0-{stamp}"), patch.object(release, "serie", "18.0"), \
                patch("odoo.addons.odoo_shield_warden.models.shield_check_cve.FEED_MAX_AGE_DAYS", 10 ** 6):
            self.assertEqual(self.check._check_cve_feed()["status"], "pass")
        # Stale data downgrades the pass to a warning.
        with patch.object(release, "version", f"18.0-{stamp}"), patch.object(release, "serie", "18.0"), \
                patch("odoo.addons.odoo_shield_warden.models.shield_check_cve.FEED_MAX_AGE_DAYS", -1):
            self.assertEqual(self.check._check_cve_feed()["status"], "warn")
        # A series the feed was never reviewed for must not pass silently.
        with patch.object(release, "version", f"19.0-{stamp}"), patch.object(release, "serie", "19.0"):
            res = self.check._check_cve_feed()
        self.assertEqual(res["status"], "warn")
        self.assertIn("not been reviewed", res["detail"])
        # Offline additions: valid ones apply, entries without a source URL are ignored and reported.
        extra = ('[{"id": "LAB-1", "series": ["18.0"], "module": "base", "published": "2026-01-01", '
                 '"fixed_build": "2999-01-01", "severity": "critical", "url": "https://example.invalid/a"},'
                 '{"id": "NO-URL", "series": ["18.0"], "module": "base", "published": "2026-01-01", "severity": "high"}]')
        self.env["ir.config_parameter"].set_param("shield.advisory_extra", extra)
        with patch.object(release, "version", f"18.0-{stamp}"), patch.object(release, "serie", "18.0"):
            res = self.check._check_cve_feed()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["severity"], "critical")
        self.assertIn("LAB-1", res["detail"])
        self.assertNotIn("NO-URL", res["detail"])
        self.env["ir.config_parameter"].set_param("shield.advisory_extra", "[{\"id\": \"NO-URL\"}]")
        with patch.object(release, "version", f"18.0-{stamp}"), patch.object(release, "serie", "18.0"):
            res = self.check._check_cve_feed()
        self.assertEqual(res["status"], "warn")
        self.assertIn("NO-URL", res["detail"])

    def test_public_attachment_on_business_document(self):
        partner = self.env["res.partner"].create({"name": "Contract holder"})
        self.env["ir.attachment"].create({"name": "contract.pdf", "res_model": "res.partner", "res_id": partner.id,
                                          "public": True, "raw": b"%PDF-1.4"})
        res = self.check._check_public_attachments()
        self.assertEqual(res["status"], "fail")
        self.assertIn("contract.pdf", res["evidence"])

    def test_deleting_audit_trail_is_logged(self):
        partner = self.env["res.partner"].create({"name": "Vendor with history"})
        message = partner.message_post(body="Bank Account #9 updated")
        message.unlink()
        log = self.env["shield.deletion.log"].search([("res_model", "=", "res.partner"), ("res_id", "=", partner.id)])
        self.assertTrue(log.record_still_exists)
        self.assertEqual(self.check._check_message_deletions()["status"], "fail")

    def test_seal_receipt_sent_off_box(self):
        self.assertEqual(self.check._check_seal_offbox()["status"], "fail")
        self.env["ir.config_parameter"].set_param("shield.seal_recipients", "auditor@example.com")
        assessment = self.env["shield.assessment"]._run()
        mail = self.env["mail.mail"].search([("subject", "=like", "[Shield seal]%")], limit=1, order="id desc")
        self.assertIn(assessment.content_hash, mail.body_html)
        self.assertEqual(mail.email_to, "auditor@example.com")
        self.assertEqual(self.check._check_seal_offbox()["status"], "pass")

    def test_one_click_fixes_for_new_checks(self):
        self.env["ir.config_parameter"].set_param("base.login_cooldown_after", 0)
        self.check._fix_login_throttling()
        self.assertEqual(self.check._check_login_throttling()["status"], "pass")
        self.clerk.groups_id |= self.env.ref("mail.group_mail_template_editor")
        self.check._fix_template_editors()
        self.assertEqual(self.check._check_template_editors()["status"], "pass")

    # -- cycle 4 -----------------------------------------------------------------------------------

    def test_login_attack_patterns(self):
        log = self.env["shield.login.log"]
        self.assertEqual(self.check._check_login_attacks()["status"], "pass")
        for _i in range(12):
            log._record("victim", "203.0.113.7", False)
        for name in ("a1", "a2", "a3", "a4", "a5"):
            log._record(name, "198.51.100.9", False)
        log._record("victim", "203.0.113.7", True)  # the guess that worked
        res = self.check._check_login_attacks()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["severity"], "critical")
        self.assertIn("account takeover", res["detail"])
        self.assertIn("password guessing against victim", res["detail"])
        self.assertIn("198.51.100.9", res["detail"])

    def test_successes_without_prior_failures_are_not_stored(self):
        self.env["shield.login.log"]._record("api_bot", "10.0.0.1", True)
        self.assertFalse(self.env["shield.login.log"].search([("login", "=", "api_bot")]))

    def test_shield_integrity_catches_sabotage(self):
        self.env["ir.config_parameter"].set_param("base.login_cooldown_after", 5)
        self.env["ir.config_parameter"].set_param("base.login_cooldown_duration", 60)
        self.env["shield.assessment"]._run()  # baseline: throttling passes
        self.assertEqual(self.check._check_shield_integrity()["status"], "pass")
        self.env["ir.config_parameter"].set_param("base.login_cooldown_after", 0)
        self.env.ref("odoo_shield_warden.ctl_dormant_users").active = False
        self.env.ref("odoo_shield_warden.cron_weekly_assessment").active = False
        res = self.check._check_shield_integrity()
        self.assertEqual(res["status"], "fail")
        self.assertIn("Brute-force protection on", res["detail"])
        self.assertIn("No dormant internal accounts", res["detail"])
        self.assertIn("schedule is switched off", res["detail"])
