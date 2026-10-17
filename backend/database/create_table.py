#!/usr/bin/env python3
"""
Direct SQL table creation script (NO ALEMBIC)
Creates scan_raw_results table using PostgreSQL raw SQL.
"""

import sys
from pathlib import Path

# Add parent directory to path to ensure imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.session import engine
from sqlalchemy import text

# --- POSTGRESQL COMPATIBLE SQL ---
SQL_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scan_raw_results (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    check_id VARCHAR(100) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    tool_name VARCHAR(50) NOT NULL,
    command_executed TEXT NOT NULL,
    raw_output TEXT,
    decision_logic TEXT NOT NULL,
    result VARCHAR(10) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
"""

SQL_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_scan_raw_results_scan_id ON scan_raw_results(scan_id);",
    "CREATE INDEX IF NOT EXISTS ix_scan_raw_results_check_id ON scan_raw_results(check_id);"
]

# Postgres verification query
SQL_VERIFY = "SELECT table_name FROM information_schema.tables WHERE table_name = 'scan_raw_results';"

def create_table():
    """Create scan_raw_results table using raw SQL."""
    print("=" * 60)
    print("Creating scan_raw_results table (PostgreSQL Mode)...")
    print("=" * 60)
    
    try:
        with engine.connect() as conn:
            # 1. Create table
            print("\n1. Creating table...")
            conn.execute(text(SQL_CREATE_TABLE))
            conn.commit()
            print("   ✓ Table created")
            
            # 2. Create indexes
            print("\n2. Creating indexes...")
            for idx, sql in enumerate(SQL_CREATE_INDEXES, 1):
                conn.execute(text(sql))
                print(f"   ✓ Index {idx}/{len(SQL_CREATE_INDEXES)} created")
            conn.commit()
            
            # 3. Verify
            print("\n3. Verifying table...")
            result = conn.execute(text(SQL_VERIFY))
            table_exists = result.fetchone()
            
            if table_exists:
                print("   ✓ Table verified: scan_raw_results exists")
                
                # Get column info (Postgres way)
                col_query = """
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = 'scan_raw_results';
                """
                column_info = conn.execute(text(col_query))
                columns = column_info.fetchall()
                
                print(f"\n   Table has {len(columns)} columns:")
                for col in columns:
                    print(f"     - {col[0]} ({col[1]})")
                
                return True
            else:
                print("   ✗ Table verification failed")
                return False
                
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

def main():
    """Main execution."""
    success = create_table()
    
    print("\n" + "=" * 60)
    if success:
        print("✓ SUCCESS: scan_raw_results table created successfully")
        print("\nNext steps:")
        print("  1. Restart your backend server")
        print("  2. Submit a new scan")
    else:
        print("✗ FAILED: Table creation unsuccessful")
        print("\nTroubleshooting:")
        print("  1. Check if 'scans' table exists (required for Foreign Key)")
        print("  2. Ensure your DATABASE_URL in config.py is correct for Postgres")
    print("=" * 60)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
