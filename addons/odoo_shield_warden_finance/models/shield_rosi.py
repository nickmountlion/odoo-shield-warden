"""Return on Security Investment (ROSI) for the money-at-risk headline.

net benefit = P x loss x (1 - recovered anyway) x hold effectiveness - annual cost
ROSI        = net benefit / annual cost

Every scenario value is a planning ESTIMATE, not a benchmark: treat them as illustrative inputs.
The licence price is a system parameter (``shield.rosi_annual_price``) so it can follow the pricing tier sold.
"""

DEFAULT_ANNUAL_PRICE = 490.0  # illustrative default, per Odoo database per year (configurable)

# key, label, annual probability of a successful incident, recovered anyway, hold effectiveness, alert-review labour per year
ROSI_SCENARIOS = (
    ("conservative", "Conservative", 0.05, 0.60, 0.50, 2500.0),
    ("base", "Base", 0.10, 0.40, 0.70, 1600.0),
    ("aggressive", "Aggressive", 0.20, 0.20, 0.80, 1000.0),
)


def rosi_calc(loss, probability, recovered, effectiveness, cost):
    """Pure maths so it can be tested and reused. Returns a dict; rosi and break-even are None when undefined."""
    avoided = probability * loss * (1 - recovered) * effectiveness
    net = avoided - cost
    per_incident = loss * (1 - recovered) * effectiveness
    breakeven = cost / per_incident if per_incident > 0 else None
    return {
        "avoided": avoided,
        "net": net,
        "rosi": net / cost if cost > 0 else None,
        "breakeven_probability": breakeven,
        "breakeven_years": (1 / breakeven) if breakeven else None,
    }
