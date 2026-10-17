from datetime import datetime, timedelta

def convert_utc_to_ist(val) -> str:
    """
    Convert a UTC datetime or ISO string to IST (UTC+5:30).
    """
    if not val:
        return "N/A"
    
    try:
        if isinstance(val, datetime):
            dt = val
        else:
            utc_iso_str = str(val)
            clean_ts = utc_iso_str.replace("Z", "").split("+")[0]
            dt = datetime.fromisoformat(clean_ts)
        
        # Check if the input is already in the future compared to UTC.
        # If it is already ahead of UTC by ~5.5 hours, it is already IST.
        now_utc = datetime.utcnow()
        # If the timestamp is more than 2 hours ahead of CURRENT UTC, 
        # it has already been converted to IST elsewhere.
        time_diff_from_utc = (dt - now_utc).total_seconds() / 3600
        
        if time_diff_from_utc > 2:
            return dt.strftime("%Y-%m-%d %H:%M:%S") + " IST"

        # Otherwise, it's a real UTC timestamp (like from the DB), so add 5:30
        ist_dt = dt + timedelta(hours=5, minutes=30)
        return ist_dt.strftime("%Y-%m-%d %H:%M:%S") + " IST"
    except Exception:
        return str(val)
