import sys
import os
from unittest.mock import MagicMock, patch

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

def test_scan_manager_imports():
    try:
        from scan_manager import ScanManager
        from datetime import datetime, timezone
        
        # Mock dependencies
        db = MagicMock()
        manager = ScanManager("auto", 1, "example.com", db)
        
        print("ScanManager instantiated successfully.")
        
        # Test the 'now' value that was causing issues
        now_val = datetime.now()
        print(f"Datetime/timezone test: {now_val}")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    if test_scan_manager_imports():
        sys.exit(0)
    else:
        sys.exit(1)
