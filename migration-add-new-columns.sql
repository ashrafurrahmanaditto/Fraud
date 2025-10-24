-- Migration script to add new columns to existing tables
-- Run this AFTER running the main schema if you get column errors

-- Ensure admin_logs table exists (in case it was missing)
CREATE TABLE IF NOT EXISTS admin_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add new columns to fingerprints table
ALTER TABLE fingerprints 
ADD COLUMN IF NOT EXISTS ml_anomaly_score DECIMAL(3,2) DEFAULT 0 CHECK (ml_anomaly_score >= 0 AND ml_anomaly_score <= 1),
ADD COLUMN IF NOT EXISTS confidence_score DECIMAL(3,2) DEFAULT 0 CHECK (confidence_score >= 0 AND confidence_score <= 1),
ADD COLUMN IF NOT EXISTS bot_signals JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS device_characteristics JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Add new columns to urls table
ALTER TABLE urls 
ADD COLUMN IF NOT EXISTS unique_visitors INTEGER DEFAULT 0 CHECK (unique_visitors >= 0),
ADD COLUMN IF NOT EXISTS last_clicked_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS ip_address INET,
ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add new columns to url_visits table
ALTER TABLE url_visits 
ADD COLUMN IF NOT EXISTS device_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS browser_name VARCHAR(50),
ADD COLUMN IF NOT EXISTS os_name VARCHAR(50),
ADD COLUMN IF NOT EXISTS is_bot BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS session_id VARCHAR(255),
ADD COLUMN IF NOT EXISTS visit_duration INTEGER,
ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add new columns to risk_logs table
ALTER TABLE risk_logs 
ADD COLUMN IF NOT EXISTS url_id UUID REFERENCES urls(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS confidence DECIMAL(3,2) DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
ADD COLUMN IF NOT EXISTS risk_score_delta INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS patterns JSONB DEFAULT '[]',
ADD COLUMN IF NOT EXISTS ip_address INET,
ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Add new columns to admin_logs table
ALTER TABLE admin_logs 
ADD COLUMN IF NOT EXISTS details JSONB DEFAULT '{}';

-- Create new tables if they don't exist
CREATE TABLE IF NOT EXISTS fraud_patterns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_name VARCHAR(100) UNIQUE NOT NULL,
    pattern_type VARCHAR(50) NOT NULL,
    description TEXT,
    severity_weight DECIMAL(3,2) DEFAULT 1.0,
    detection_rules JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ml_analysis_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE CASCADE,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    anomaly_score DECIMAL(3,2) NOT NULL CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
    confidence DECIMAL(3,2) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    features JSONB DEFAULT '{}',
    explanation TEXT,
    is_anomaly BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    country VARCHAR(2),
    city VARCHAR(100),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    duration INTEGER,
    page_views INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'
);

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_fingerprints_ml_anomaly_score ON fingerprints(ml_anomaly_score);
CREATE INDEX IF NOT EXISTS idx_fingerprints_last_activity ON fingerprints(last_activity);
CREATE INDEX IF NOT EXISTS idx_urls_last_clicked_at ON urls(last_clicked_at);
CREATE INDEX IF NOT EXISTS idx_url_visits_is_bot ON url_visits(is_bot);
CREATE INDEX IF NOT EXISTS idx_url_visits_country ON url_visits(country);
CREATE INDEX IF NOT EXISTS idx_url_visits_device_type ON url_visits(device_type);
CREATE INDEX IF NOT EXISTS idx_risk_logs_severity ON risk_logs(severity);
CREATE INDEX IF NOT EXISTS idx_fraud_patterns_pattern_name ON fraud_patterns(pattern_name);
CREATE INDEX IF NOT EXISTS idx_fraud_patterns_is_active ON fraud_patterns(is_active);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_fingerprint_id ON ml_analysis_results(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_created_at ON ml_analysis_results(created_at);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_anomaly_score ON ml_analysis_results(anomaly_score);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint_id ON sessions(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Enable RLS on new tables
ALTER TABLE fraud_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Add RLS policies for new tables
CREATE POLICY "Admin can view fraud patterns" ON fraud_patterns
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can manage fraud patterns" ON fraud_patterns
    FOR ALL USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can view ML analysis results" ON ml_analysis_results
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can create ML analysis results" ON ml_analysis_results
    FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Public can create sessions" ON sessions
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Admin can view all sessions" ON sessions
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can manage sessions" ON sessions
    FOR ALL USING (auth.role() = 'authenticated');

-- Update functions to handle new columns safely
CREATE OR REPLACE FUNCTION get_dashboard_stats() RETURNS JSONB AS $$
DECLARE
    stats JSONB;
BEGIN
    SELECT jsonb_build_object(
        'total_urls', (SELECT COUNT(*) FROM urls WHERE is_active = TRUE),
        'total_visits', (SELECT COUNT(*) FROM url_visits),
        'total_fingerprints', (SELECT COUNT(*) FROM fingerprints),
        'high_risk_fingerprints', (SELECT COUNT(*) FROM fingerprints WHERE risk_score >= 5),
        'ml_anomalies', (SELECT COUNT(*) FROM fingerprints WHERE COALESCE(ml_anomaly_score, 0) > 0.5),
        'bot_detections', (SELECT COUNT(*) FROM url_visits WHERE COALESCE(is_bot, false) = TRUE),
        'recent_urls_24h', (SELECT COUNT(*) FROM urls WHERE created_at > NOW() - INTERVAL '24 hours'),
        'recent_visits_24h', (SELECT COUNT(*) FROM url_visits WHERE visited_at > NOW() - INTERVAL '24 hours'),
        'risk_events_24h', (SELECT COUNT(*) FROM risk_logs WHERE created_at > NOW() - INTERVAL '24 hours'),
        'active_rate_limits', (SELECT COUNT(*) FROM rate_limits WHERE window_start > NOW() - INTERVAL '1 hour'),
        'active_sessions', (SELECT COUNT(*) FROM sessions WHERE COALESCE(is_active, false) = TRUE),
        'unique_visitors_24h', (SELECT COUNT(DISTINCT fingerprint_id) FROM url_visits WHERE visited_at > NOW() - INTERVAL '24 hours')
    ) INTO stats;
    
    RETURN stats;
END;
$$ LANGUAGE plpgsql;

-- Update views to handle new columns safely
DROP VIEW IF EXISTS url_stats CASCADE;
CREATE VIEW url_stats AS
SELECT 
    u.id,
    u.original_url,
    u.short_code,
    u.click_count,
    COALESCE(u.unique_visitors, 0) as unique_visitors,
    u.created_at,
    u.expires_at,
    u.is_active,
    u.last_clicked_at,
    f.visitor_id,
    f.risk_score,
    COALESCE(f.ml_anomaly_score, 0) as ml_anomaly_score,
    f.browser_info->>'userAgent' as browser,
    COUNT(v.id) as total_visits,
    MAX(v.visited_at) as last_visit,
    COUNT(DISTINCT v.fingerprint_id) as unique_fingerprints
FROM urls u
LEFT JOIN fingerprints f ON u.fingerprint_id = f.id
LEFT JOIN url_visits v ON u.id = v.url_id
GROUP BY u.id, f.visitor_id, f.risk_score, f.ml_anomaly_score, f.browser_info, u.unique_visitors, u.last_clicked_at;

DROP VIEW IF EXISTS fingerprint_stats CASCADE;
CREATE VIEW fingerprint_stats AS
SELECT 
    f.id,
    f.visitor_id,
    f.risk_score,
    COALESCE(f.ml_anomaly_score, 0) as ml_anomaly_score,
    COALESCE(f.confidence_score, 0) as confidence_score,
    f.created_at,
    f.updated_at,
    COALESCE(f.last_activity, f.created_at) as last_activity,
    COUNT(DISTINCT u.id) as url_count,
    COUNT(DISTINCT v.id) as visit_count,
    COUNT(DISTINCT rl.id) as risk_log_count,
    MAX(rl.created_at) as last_risk_event,
    MAX(v.visited_at) as last_visit,
    f.device_info->>'userAgent' as user_agent,
    f.device_info->>'platform' as platform,
    f.device_info->>'mobile' as is_mobile
FROM fingerprints f
LEFT JOIN urls u ON f.id = u.fingerprint_id AND u.is_active = TRUE
LEFT JOIN url_visits v ON f.id = v.fingerprint_id
LEFT JOIN risk_logs rl ON f.id = rl.fingerprint_id
GROUP BY f.id, f.visitor_id, f.risk_score, f.ml_anomaly_score, f.confidence_score, f.created_at, f.updated_at, f.last_activity, f.device_info;

DROP VIEW IF EXISTS fraud_analysis_view CASCADE;
CREATE VIEW fraud_analysis_view AS
SELECT 
    f.id,
    f.visitor_id,
    f.risk_score,
    COALESCE(f.ml_anomaly_score, 0) as ml_anomaly_score,
    f.created_at,
    COUNT(DISTINCT rl.id) as total_risk_events,
    COUNT(DISTINCT CASE WHEN rl.severity >= 4 THEN rl.id END) as high_severity_events,
    MAX(rl.created_at) as last_risk_event,
    jsonb_agg(DISTINCT rl.risk_type) as risk_types,
    jsonb_agg(DISTINCT rl.patterns) as patterns
FROM fingerprints f
LEFT JOIN risk_logs rl ON f.id = rl.fingerprint_id
WHERE f.risk_score >= 3 OR COALESCE(f.ml_anomaly_score, 0) > 0.3
GROUP BY f.id, f.visitor_id, f.risk_score, f.ml_anomaly_score, f.created_at;

-- Insert sample fraud patterns
INSERT INTO fraud_patterns (pattern_name, pattern_type, description, severity_weight, detection_rules) VALUES
('duplicate_fingerprint', 'device_reuse', 'Same fingerprint used across multiple accounts', 4.0, '{"threshold": 1, "time_window": "24h"}'),
('high_velocity', 'behavior', 'Rapid URL creation pattern', 3.0, '{"threshold": 10, "time_window": "1h"}'),
('bot_detection', 'automation', 'Automation tools detected', 5.0, '{"signals": ["webdriver", "selenium", "phantom"]}'),
('click_fraud', 'behavior', 'Suspicious click patterns', 3.5, '{"threshold": 50, "time_window": "1h"}'),
('device_anomaly', 'device', 'Unusual device characteristics', 2.5, '{"checks": ["resolution", "hardware", "capabilities"]}')
ON CONFLICT (pattern_name) DO NOTHING;

-- Recreate triggers to handle new columns
DROP TRIGGER IF EXISTS trigger_update_risk_score_urls ON urls;
CREATE TRIGGER trigger_update_risk_score_urls
    AFTER INSERT OR UPDATE ON urls
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

DROP TRIGGER IF EXISTS trigger_update_risk_score_visits ON url_visits;
CREATE TRIGGER trigger_update_risk_score_visits
    AFTER INSERT ON url_visits
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

DROP TRIGGER IF EXISTS trigger_update_risk_score_logs ON risk_logs;
CREATE TRIGGER trigger_update_risk_score_logs
    AFTER INSERT ON risk_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

DROP TRIGGER IF EXISTS trigger_update_fingerprint_last_activity_urls ON urls;
CREATE TRIGGER trigger_update_fingerprint_last_activity_urls
    AFTER INSERT ON urls
    FOR EACH ROW
    EXECUTE FUNCTION update_fingerprint_last_activity();

DROP TRIGGER IF EXISTS trigger_update_fingerprint_last_activity_visits ON url_visits;
CREATE TRIGGER trigger_update_fingerprint_last_activity_visits
    AFTER INSERT ON url_visits
    FOR EACH ROW
    EXECUTE FUNCTION update_fingerprint_last_activity();

DROP TRIGGER IF EXISTS trigger_update_url_stats ON url_visits;
CREATE TRIGGER trigger_update_url_stats
    AFTER INSERT ON url_visits
    FOR EACH ROW
    EXECUTE FUNCTION update_url_stats();

-- Recreate RLS policies to handle new columns
DROP POLICY IF EXISTS "Admin can view fraud patterns" ON fraud_patterns;
CREATE POLICY "Admin can view fraud patterns" ON fraud_patterns
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can manage fraud patterns" ON fraud_patterns;
CREATE POLICY "Admin can manage fraud patterns" ON fraud_patterns
    FOR ALL USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can view ML analysis results" ON ml_analysis_results;
CREATE POLICY "Admin can view ML analysis results" ON ml_analysis_results
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can create ML analysis results" ON ml_analysis_results;
CREATE POLICY "Admin can create ML analysis results" ON ml_analysis_results
    FOR INSERT WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Public can create sessions" ON sessions;
CREATE POLICY "Public can create sessions" ON sessions
    FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Admin can view all sessions" ON sessions;
CREATE POLICY "Admin can view all sessions" ON sessions
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can manage sessions" ON sessions;
CREATE POLICY "Admin can manage sessions" ON sessions
    FOR ALL USING (auth.role() = 'authenticated');

-- Grant permissions
GRANT ALL ON fraud_patterns TO anon, authenticated;
GRANT ALL ON ml_analysis_results TO anon, authenticated;
GRANT ALL ON sessions TO anon, authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated;
