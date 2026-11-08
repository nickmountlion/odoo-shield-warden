from datetime import timedelta

from odoo import fields
from odoo.exceptions import UserError
from odoo.tests import TransactionCase, tagged


@tagged("post_install", "-at_install")
class TestShield(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.Assessment = cls.env["shield.assessment"]
        cls.Finding = cls.env["shield.finding"]

    def _result(self, assessment, code):
        return assessment.result_ids.filtered(lambda r: r.control_id.code == code)

    def test_every_control_runs(self):
        assessment = self.Assessment._run()
        controls = self.env["shield.control"].search([])
        self.assertEqual(len(assessment.result_ids), len(controls))
        errors = assessment.result_ids.filtered(lambda r: r.status == "error")
        self.assertFalse(errors, "Checks raised errors: %s" % errors.mapped(lambda r: f"{r.control_id.code}: {r.detail}"))
        self.assertTrue(0 <= assessment.security_score <= 100)
        self.assertEqual(len(assessment.framework_score_ids), 3)

    def test_findings_lifecycle(self):
        self.env["ir.config_parameter"].set_param("auth_signup.invitation_scope", "b2c")
        assessment = self.Assessment._run()
        if self._result(assessment, "signup_open").status == "na":
            self.skipTest("auth_signup not installed")
        finding = self.Finding.search([("control_id.code", "=", "signup_open")])
        self.assertEqual(finding.state, "open")

        finding.action_apply_fix()
        self.assertEqual(finding.state, "resolved")
        self.assertEqual(self.env["ir.config_parameter"].get_param("auth_signup.invitation_scope"), "b2b")

        # Regression reopens the same finding instead of creating a new one.
        self.env["ir.config_parameter"].set_param("auth_signup.invitation_scope", "b2c")
        self.Assessment._run()
        self.assertEqual(finding.state, "open")
        self.assertEqual(self.Finding.search_count([("control_id.code", "=", "signup_open")]), 1)

    def test_attestation_satisfies_manual_control(self):
        control = self.env.ref("odoo_shield_warden.ctl_incident_response")
        before = self._result(self.Assessment._run(), "incident_response")
        self.assertEqual(before.status, "fail")
        self.env["shield.attestation"].create({"control_id": control.id, "evidence": "<p>Plan v1 rehearsed</p>"})
        after = self._result(self.Assessment._run(), "incident_response")
        self.assertEqual(after.status, "pass")

    def test_expired_attestation_fails(self):
        control = self.env.ref("odoo_shield_warden.ctl_restore_tested")
        self.env["shield.attestation"].create({
            "control_id": control.id, "date": fields.Date.today() - timedelta(days=200)})
        res = self._result(self.Assessment._run(), "restore_tested")
        self.assertEqual(res.status, "fail")
        self.assertIn("expired", res.detail)

    def test_risk_acceptance_counts_for_grc_not_security(self):
        first = self.Assessment._run()
        finding = self.Finding.search([("state", "=", "open"), ("severity", "!=", "critical")], limit=1)
        self.assertTrue(finding)
        with self.assertRaises(UserError):
            finding.action_accept_risk()
        finding.write({"acceptance_reason": "Compensating control: VPN only",
                       "acceptance_expiry": fields.Date.today() + timedelta(days=30)})
        finding.action_accept_risk()
        second = self.Assessment._run()
        self.assertEqual(second.security_score, first.security_score)
        self.assertGreaterEqual(second.grc_score, first.grc_score)

        finding.acceptance_expiry = fields.Date.today() - timedelta(days=1)
        self.Finding._cron_expire_acceptances()
        self.assertEqual(finding.state, "open")

    def test_evidence_chain_detects_tampering(self):
        first = self.Assessment._run()
        second = self.Assessment._run()
        self.assertEqual(second.previous_hash, first.content_hash)
        self.assertEqual(second.action_verify_chain()["params"]["type"], "success")
        # Someone with database access quietly turns a failure into a pass.
        failing = first.result_ids.filtered(lambda r: r.status == "fail")[:1]
        with self.assertRaises(UserError):  # the ORM refuses ...
            failing.write({"status": "pass"})
        self.env.cr.execute("UPDATE shield_assessment_result SET status='pass' WHERE id=%s", failing.ids)  # ... SQL does not
        self.env.invalidate_all()
        self.assertEqual(second.action_verify_chain()["params"]["type"], "danger")

    def test_scorecard_renders(self):
        assessment = self.Assessment._run()
        html, _fmt = self.env["ir.actions.report"]._render_qweb_html(
            "odoo_shield_warden.report_scorecard", assessment.ids)
        self.assertIn(b"Security score", html)
