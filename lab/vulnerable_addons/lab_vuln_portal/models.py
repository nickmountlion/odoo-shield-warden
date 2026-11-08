# LAB FIXTURE - DELIBERATELY VULNERABLE.
from odoo import fields, models


class LabPortalNote(models.Model):
    _name = "lab.portal.note"
    _description = "Lab portal note"

    name = fields.Char()
    body = fields.Html(sanitize=False)  # stored XSS sink
