-- Bazel-Firecracker Runner Database Schema
-- Run this against a PostgreSQL 15+ database

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Hosts table: tracks Firecracker host VMs
CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_name VARCHAR(255) UNIQUE NOT NULL,
    zone VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'ready' CHECK (status IN ('ready', 'draining', 'unhealthy', 'terminating')),
    total_slots INT DEFAULT 0,
    used_slots INT DEFAULT 0,
    idle_runners INT DEFAULT 0,
    busy_runners INT DEFAULT 0,
    snapshot_version VARCHAR(255),
    grpc_address VARCHAR(255),
    http_address VARCHAR(255),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Runners table: tracks individual runner microVMs
CREATE TABLE IF NOT EXISTS runners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
    status VARCHAR(32) DEFAULT 'pending' CHECK (status IN ('pending', 'booting', 'initializing', 'idle', 'busy', 'draining', 'quarantined', 'retiring', 'terminated')),
    internal_ip VARCHAR(45),
    github_runner_id VARCHAR(255),
    job_id VARCHAR(255),
    repo VARCHAR(512),
    branch VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Snapshots table: tracks snapshot versions
CREATE TABLE IF NOT EXISTS snapshots (
    version VARCHAR(255) PRIMARY KEY,
    status VARCHAR(32) DEFAULT 'building' CHECK (status IN ('building', 'ready', 'active', 'deprecated', 'failed')),
    gcs_path VARCHAR(512),
    bazel_version VARCHAR(32),
    repo_commit VARCHAR(64),
    size_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metrics JSONB DEFAULT '{}'::jsonb
);

-- Jobs table: tracks CI job requests (optional, for queue-based allocation)
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_workflow_run_id BIGINT,
    github_job_id BIGINT,
    repo VARCHAR(512) NOT NULL,
    branch VARCHAR(255),
    commit_sha VARCHAR(64),
    status VARCHAR(32) DEFAULT 'queued' CHECK (status IN ('queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')),
    runner_id UUID REFERENCES runners(id) ON DELETE SET NULL,
    labels JSONB DEFAULT '[]'::jsonb,
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_heartbeat ON hosts(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_hosts_instance_name ON hosts(instance_name);

CREATE INDEX IF NOT EXISTS idx_runners_host ON runners(host_id);
CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);
CREATE INDEX IF NOT EXISTS idx_runners_job ON runners(job_id);

CREATE INDEX IF NOT EXISTS idx_snapshots_status ON snapshots(status);
CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_queued ON jobs(queued_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_jobs_runner ON jobs(runner_id);

-- Trigger to update updated_at on hosts
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS hosts_updated_at ON hosts;
CREATE TRIGGER hosts_updated_at
    BEFORE UPDATE ON hosts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- Views for monitoring
CREATE OR REPLACE VIEW host_summary AS
SELECT 
    COUNT(*) as total_hosts,
    COUNT(*) FILTER (WHERE status = 'ready') as ready_hosts,
    COUNT(*) FILTER (WHERE status = 'draining') as draining_hosts,
    COUNT(*) FILTER (WHERE status = 'unhealthy') as unhealthy_hosts,
    SUM(total_slots) as total_slots,
    SUM(used_slots) as used_slots,
    SUM(idle_runners) as idle_runners,
    SUM(busy_runners) as busy_runners
FROM hosts
WHERE last_heartbeat > NOW() - INTERVAL '2 minutes';

CREATE OR REPLACE VIEW runner_summary AS
SELECT 
    status,
    COUNT(*) as count,
    AVG(EXTRACT(EPOCH FROM (NOW() - created_at))) as avg_age_seconds
FROM runners
GROUP BY status;

CREATE OR REPLACE VIEW snapshot_summary AS
SELECT 
    version,
    status,
    size_bytes,
    created_at,
    metrics->>'cache_hit_ratio' as cache_hit_ratio,
    metrics->>'avg_analysis_time_ms' as avg_analysis_time_ms
FROM snapshots
ORDER BY created_at DESC
LIMIT 10;

-- Grant permissions (adjust as needed)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO firecracker_app;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO firecracker_app;

COMMENT ON TABLE hosts IS 'GCE VMs running Firecracker and hosting microVMs';
COMMENT ON TABLE runners IS 'Individual GitHub runner microVMs';
COMMENT ON TABLE snapshots IS 'Firecracker snapshot versions for fast VM boot';
COMMENT ON TABLE jobs IS 'CI job queue for runner allocation';

