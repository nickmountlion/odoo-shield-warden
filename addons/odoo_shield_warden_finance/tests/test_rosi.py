from odoo.tests import TransactionCase, tagged

from ..models.shield_rosi import rosi_calc


@tagged("post_install", "-at_install")
class TestRosi(TransactionCase):

    def test_math_matches_research_table(self):
        # 18,400 loss, conservative / base / aggressive, all-in cost 3,000 / 2,100 / 1,500
        cons = rosi_calc(18400, 0.05, 0.60, 0.50, 3000)
        base = rosi_calc(18400, 0.10, 0.40, 0.70, 2100)
        aggr = rosi_calc(18400, 0.20, 0.20, 0.80, 1500)
        self.assertAlmostEqual(cons["net"], -2816, delta=1)
        self.assertAlmostEqual(base["net"], -1327.2, delta=1)
        self.assertAlmostEqual(aggr["rosi"], 0.57, delta=0.01)
        self.assertAlmostEqual(base["breakeven_probability"], 0.272, delta=0.001)

    def test_undefined_cases_do_not_crash(self):
        self.assertIsNone(rosi_calc(0, 0.1, 0.4, 0.7, 2100)["breakeven_probability"])
        self.assertIsNone(rosi_calc(1000, 0.1, 0.4, 0.7, 0)["rosi"])

    def test_assessment_rosi_uses_price_parameter(self):
        assessment = self.env["shield.assessment"].create({"transaction_exposure": 18400})
        self.env["ir.config_parameter"].sudo().set_param("shield.rosi_annual_price", "490")
        base = next(r for r in assessment.rosi_scenarios() if r["key"] == "base")
        self.assertAlmostEqual(base["cost"], 2090)
        self.env["ir.config_parameter"].sudo().set_param("shield.rosi_annual_price", "1490")
        base = next(r for r in assessment.rosi_scenarios() if r["key"] == "base")
        self.assertAlmostEqual(base["cost"], 3090)
        self.assertIn("Base", assessment.rosi_html)
        assessment.transaction_exposure = 0
        self.assertFalse(assessment.rosi_html)
