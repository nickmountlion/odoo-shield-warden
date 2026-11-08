{
    "name": "Odoo Shield Warden: Money at Risk",
    "summary": "Who could commit payment fraud in your Odoo, who actually did something risky, and how much money it touched",
    "description": """
Continuous controls monitoring for Odoo Accounting.

* Access risk computed from effective permissions (access rules and trust rights), not group names:
  Redirect & Pay, Escalate & Pay, Bill & Pay, with the payment volume each conflicted user really processed.
* Transaction monitoring on real data: vendor bank account changed shortly before a payment,
  bank accounts trusted by the same person who changed them, bills paid by the person who entered them,
  duplicate vendor bills, bank changes hidden from the audit trail, and one IBAN/CBU shared by unrelated contacts.
* Payment hold: payments to freshly changed bank details need second-person verification.
* ROSI view: net benefit, ROSI and break-even chance from the money at risk; the licence price is a system parameter.
* Alerts grouped into cases per bank account, payment or bill; every case carries an amount in company currency and a review workflow, so assessments report money at risk.
""",
    "version": "18.0.1.3.0",
    "category": "Productivity/Security",
    "author": "Odoo Shield Warden",
    "license": "Other proprietary",
    "depends": ["odoo_shield_warden", "account"],
    "data": [
        "security/ir.model.access.csv",
        "data/shield_finance_controls.xml",
        "data/shield_finance_controls_threats.xml",
        "data/shield_finance_controls_cycle3.xml",
        "views/shield_finance_views.xml",
        "views/shield_case_views.xml",
        "report/shield_finance_report.xml",
    ],
    "auto_install": True,
    "installable": True,
}
