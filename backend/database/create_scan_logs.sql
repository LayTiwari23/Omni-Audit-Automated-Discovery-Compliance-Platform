-- =====================================================
-- Create scan_logs table for live progress tracking
-- Run this SQL in your PostgreSQL database
-- =====================================================

CREATE TABLE IF NOT EXISTS scan_logs (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at);

-- Verify table creation
-- SELECT * FROM scan_logs LIMIT 1;
