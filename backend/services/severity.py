"""Incident severity classification (INDS-64).

Turns a risk score (0 to 100) into a severity level,
using the thresholds from SDD section 6.1.
"""

LEVELS = ["Low", "Medium", "High", "Critical"]


def classify_severity(score, trusted=False):
    """Return "Low", "Medium", "High" or "Critical" for a risk score.

    Low 0-29, Medium 30-54, High 55-79, Critical 80-100.
    If the source device is trusted, the level is lowered by one
    (Low stays Low).
    """
    if score < 0 or score > 100:
        raise ValueError("score must be between 0 and 100")

    if score >= 80:
        level = 3
    elif score >= 55:
        level = 2
    elif score >= 30:
        level = 1
    else:
        level = 0

    if trusted and level > 0:
        level = level - 1

    return LEVELS[level]