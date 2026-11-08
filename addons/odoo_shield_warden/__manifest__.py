{
    "name": "Odoo Shield Warden: Security & GRC",
    "summary": "Assess, harden and evidence the security of your Odoo against ISO 27001, SOC 2 and CIS Controls",
    "description": """
Continuous security assessment for Odoo Enterprise and Community (self-hosted and Odoo.sh).

* Automated checks: authentication, privileged access, platform configuration, encryption in transit, monitoring, vulnerability and upgrade posture.
* Manual controls with evidence-backed attestations (backups, restore tests, access reviews, incident response, change management).
* Findings register with owners, due dates, risk acceptance with expiry, automatic resolution and regression detection.
* One-click hardening for safe fixes, logged in the chatter.
* Security Score and GRC compliance per framework, with a PDF scorecard.
""",
    "version": "18.0.1.3.0",
    "category": "Productivity/Security",
    "author": "Odoo Shield Warden",
    "license": "Other proprietary",
    "depends": ["base", "mail", "web"],
    "data": [
        "security/shield_groups.xml",
        "security/ir.model.access.csv",
        "data/shield_frameworks.xml",
        "data/shield_controls.xml",
        "data/shield_controls_threats.xml",
        "data/shield_controls_cycle3.xml",
        "data/shield_controls_cycle4.xml",
        "data/shield_cron.xml",
        "views/shield_assessment_views.xml",
        "views/shield_finding_views.xml",
        "views/shield_control_views.xml",
        "views/shield_attestation_views.xml",
        "views/shield_framework_views.xml",
        "views/shield_export_log_views.xml",
        "views/shield_deletion_log_views.xml",
        "views/shield_login_log_views.xml",
        "report/shield_report.xml",
        "views/shield_menus.xml",
    ],
    "application": True,
    "installable": True,
}
