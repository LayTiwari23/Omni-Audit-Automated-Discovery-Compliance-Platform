"""
email_engine — Email compliance scanning engine.

Public API (what scan_manager.py needs):

    from engines.email_engine import run_email_engine

    run_email_engine(
        db       = db_session,
        scan_id  = 42,
        domain   = "example.com",
    )
"""

from .engine import run_email_engine

__all__ = ["run_email_engine"]
