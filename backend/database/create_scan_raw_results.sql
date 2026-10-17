-- =============================================
-- Raw SQL Table Creation for scan_raw_results
-- NO ALEMBIC - Direct SQL execution
-- =============================================


-- ==================== PostgreSQL Version ====================
-- Run with: psql -U compliance_user -d compliance_db -f create_scan_raw_results.sql

 CREATE TABLE IF NOT EXISTS scan_raw_results (
     id SERIAL PRIMARY KEY,
     scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
     check_id INTEGER NOT NULL,
     check_name VARCHAR(255) NOT NULL,
     tool_name VARCHAR(50) NOT NULL,
     command_executed TEXT NOT NULL,
     raw_output TEXT,
     decision_logic TEXT NOT NULL,
     result VARCHAR(10) NOT NULL,
     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
 );

 CREATE INDEX IF NOT EXISTS ix_scan_raw_results_id ON scan_raw_results(id);
 CREATE INDEX IF NOT EXISTS ix_scan_raw_results_scan_id ON scan_raw_results(scan_id);
 CREATE INDEX IF NOT EXISTS ix_scan_raw_results_check_id ON scan_raw_results(check_id);


-- ==================== Verification Query ====================
-- Run after creation to verify table exists:
-- SQLite: sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_raw_results';"
-- PostgreSQL: psql -U compliance_user -d compliance_db -c "\d scan_raw_results"

-- Sample query to check structure:
-- SELECT * FROM scan_raw_results LIMIT 1;
