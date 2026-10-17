"""
remediation_engine.py – Retrieves remediation guidance for compliance checks.
"""

import logging
from . import remediation_db

logger = logging.getLogger(__name__)

def get_remediation(check_id: int, finding_details: dict = None) -> dict:
    """
    Return remediation dict for a check_id from the static database.
    AI/ML dynamic remediation has been disabled.
    """
    # Get static fallback
    rem = remediation_db.REMEDIATION_MAP.get(check_id, {
        "fix": "No specific remediation available for this check. Review the decision logic and consult security best practices.",
        "example": "",
        "reference": ""
    }).copy() # Copy to avoid mutating the DB map

    return rem
