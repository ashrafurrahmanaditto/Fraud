-- Supabase Database Schema for URL Shortener with Fraud Detection
-- Run this script in your Supabase SQL Editor

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (optional for user accounts)
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Fingerprints table to store device fingerprints with enhanced fields
CREATE TABLE IF NOT EXISTS fingerprints (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    visitor_id VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    browser_info JSONB,
    device_info JSONB,
    user_agent TEXT,
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 10),
    ml_anomaly_score DECIMAL(3,2) DEFAULT 0 CHECK (ml_anomaly_score >= 0 AND ml_anomaly_score <= 1),
    confidence_score DECIMAL(3,2) DEFAULT 0 CHECK (confidence_score >= 0 AND confidence_score <= 1),
    bot_signals JSONB DEFAULT '{}',
    device_characteristics JSONB DEFAULT '{}',
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- URLs table to store shortened URLs with enhanced tracking
CREATE TABLE IF NOT EXISTS urls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_url TEXT NOT NULL,
    short_code VARCHAR(10) UNIQUE NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE SET NULL,
    click_count INTEGER DEFAULT 0 CHECK (click_count >= 0),
    unique_visitors INTEGER DEFAULT 0 CHECK (unique_visitors >= 0),
    last_clicked_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'
);

-- URL visits table to track every click with enhanced analytics
CREATE TABLE IF NOT EXISTS url_visits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url_id UUID REFERENCES urls(id) ON DELETE CASCADE,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE SET NULL,
    ip_address INET,
    referrer TEXT,
    user_agent TEXT,
    country VARCHAR(2),
    city VARCHAR(100),
    device_type VARCHAR(50), -- mobile, desktop, tablet
    browser_name VARCHAR(50),
    os_name VARCHAR(50),
    is_bot BOOLEAN DEFAULT FALSE,
    session_id VARCHAR(255),
    visit_duration INTEGER, -- seconds
    visited_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Risk logs table for suspicious activity with enhanced tracking
CREATE TABLE IF NOT EXISTS risk_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE SET NULL,
    url_id UUID REFERENCES urls(id) ON DELETE SET NULL,
    risk_type VARCHAR(50) NOT NULL CHECK (risk_type IN (
        'duplicate_fingerprint', 
        'multiple_accounts', 
        'spam_attempt', 
        'suspicious_pattern',
        'rapid_creation',
        'high_velocity',
        'extreme_velocity',
        'burst_pattern',
        'high_visit_volume',
        'rapid_clicking',
        'direct_access',
        'suspicious_url',
        'webdriver',
        'phantom',
        'selenium',
        'headless',
        'automation',
        'mobile_desktop_mismatch',
        'touch_mismatch',
        'unusual_resolution',
        'no_webgl',
        'no_storage',
        'missing_hardware',
        'no_plugins',
        'similar_device_signature',
        'comprehensive_fraud_detection',
        'ml_anomaly_detected'
    )),
    description TEXT,
    severity INTEGER DEFAULT 1 CHECK (severity >= 1 AND severity <= 5),
    confidence DECIMAL(3,2) DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
    risk_score_delta INTEGER DEFAULT 0,
    patterns JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fingerprint_id UUID REFERENCES fingerprints(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN (
        'url_creation', 
        'admin_access', 
        'url_visit',
        'api_call'
    )),
    attempts INTEGER DEFAULT 1 CHECK (attempts >= 0),
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(fingerprint_id, action_type)
);

-- Admin logs table for audit trail
DROP TABLE IF EXISTS admin_logs CASCADE;
CREATE TABLE admin_logs (
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

-- Fraud patterns table for pattern analysis
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

-- ML model results table for storing ML analysis results
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

-- Session tracking table
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
    duration INTEGER, -- seconds
    page_views INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_fingerprints_visitor_id ON fingerprints(visitor_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_risk_score ON fingerprints(risk_score);
CREATE INDEX IF NOT EXISTS idx_fingerprints_ml_anomaly_score ON fingerprints(ml_anomaly_score);
CREATE INDEX IF NOT EXISTS idx_fingerprints_created_at ON fingerprints(created_at);
CREATE INDEX IF NOT EXISTS idx_fingerprints_last_activity ON fingerprints(last_activity);
CREATE INDEX IF NOT EXISTS idx_urls_short_code ON urls(short_code);
CREATE INDEX IF NOT EXISTS idx_urls_created_at ON urls(created_at);
CREATE INDEX IF NOT EXISTS idx_urls_fingerprint_id ON urls(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_urls_is_active ON urls(is_active);
CREATE INDEX IF NOT EXISTS idx_urls_last_clicked_at ON urls(last_clicked_at);
CREATE INDEX IF NOT EXISTS idx_url_visits_url_id ON url_visits(url_id);
CREATE INDEX IF NOT EXISTS idx_url_visits_visited_at ON url_visits(visited_at);
CREATE INDEX IF NOT EXISTS idx_url_visits_fingerprint_id ON url_visits(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_url_visits_is_bot ON url_visits(is_bot);
CREATE INDEX IF NOT EXISTS idx_url_visits_country ON url_visits(country);
CREATE INDEX IF NOT EXISTS idx_url_visits_device_type ON url_visits(device_type);
CREATE INDEX IF NOT EXISTS idx_risk_logs_fingerprint_id ON risk_logs(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_risk_logs_created_at ON risk_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_risk_logs_risk_type ON risk_logs(risk_type);
CREATE INDEX IF NOT EXISTS idx_risk_logs_severity ON risk_logs(severity);
CREATE INDEX IF NOT EXISTS idx_rate_limits_fingerprint_action ON rate_limits(fingerprint_id, action_type);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin_id ON admin_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_fraud_patterns_pattern_name ON fraud_patterns(pattern_name);
CREATE INDEX IF NOT EXISTS idx_fraud_patterns_is_active ON fraud_patterns(is_active);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_fingerprint_id ON ml_analysis_results(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_created_at ON ml_analysis_results(created_at);
CREATE INDEX IF NOT EXISTS idx_ml_analysis_anomaly_score ON ml_analysis_results(anomaly_score);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint_id ON sessions(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Function to generate short codes
CREATE OR REPLACE FUNCTION generate_short_code() RETURNS TEXT AS $$
DECLARE
    chars TEXT := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    result TEXT := '';
    i INTEGER;
    max_attempts INTEGER := 100;
    attempts INTEGER := 0;
BEGIN
    LOOP
        result := '';
        FOR i IN 1..6 LOOP
            result := result || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
        END LOOP;
        
        -- Check if code already exists
        IF NOT EXISTS (SELECT 1 FROM urls WHERE short_code = result) THEN
            RETURN result;
        END IF;
        
        attempts := attempts + 1;
        IF attempts >= max_attempts THEN
            RAISE EXCEPTION 'Unable to generate unique short code after % attempts', max_attempts;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate risk score
CREATE OR REPLACE FUNCTION calculate_risk_score(fingerprint_uuid UUID) RETURNS INTEGER AS $$
DECLARE
    score INTEGER := 0;
    url_count INTEGER;
    visit_count INTEGER;
    risk_log_count INTEGER;
    duplicate_fingerprint_count INTEGER;
    rapid_creation_count INTEGER;
    recent_risk_logs INTEGER;
BEGIN
    -- Count URLs created by this fingerprint
    SELECT COUNT(*) INTO url_count FROM urls WHERE fingerprint_id = fingerprint_uuid AND is_active = TRUE;
    IF url_count > 20 THEN
        score := score + 3;
    ELSIF url_count > 10 THEN
        score := score + 2;
    ELSIF url_count > 5 THEN
        score := score + 1;
    END IF;
    
    -- Count total visits from this fingerprint
    SELECT COUNT(*) INTO visit_count FROM url_visits WHERE fingerprint_id = fingerprint_uuid;
    IF visit_count > 200 THEN
        score := score + 3;
    ELSIF visit_count > 100 THEN
        score := score + 2;
    ELSIF visit_count > 50 THEN
        score := score + 1;
    END IF;
    
    -- Count risk logs
    SELECT COUNT(*) INTO risk_log_count FROM risk_logs WHERE fingerprint_id = fingerprint_uuid;
    score := score + risk_log_count;
    
    -- Check for duplicate fingerprints (same visitor_id)
    SELECT COUNT(*) INTO duplicate_fingerprint_count 
    FROM fingerprints 
    WHERE visitor_id = (SELECT visitor_id FROM fingerprints WHERE id = fingerprint_uuid);
    
    IF duplicate_fingerprint_count > 1 THEN
        score := score + 4;
    END IF;
    
    -- Check for rapid URL creation (last hour)
    SELECT COUNT(*) INTO rapid_creation_count 
    FROM urls 
    WHERE fingerprint_id = fingerprint_uuid 
    AND created_at > NOW() - INTERVAL '1 hour';
    
    IF rapid_creation_count > 5 THEN
        score := score + 2;
    END IF;
    
    -- Check for recent risk logs (last 24 hours)
    SELECT COUNT(*) INTO recent_risk_logs 
    FROM risk_logs 
    WHERE fingerprint_id = fingerprint_uuid 
    AND created_at > NOW() - INTERVAL '24 hours';
    
    IF recent_risk_logs > 3 THEN
        score := score + 2;
    END IF;
    
    RETURN LEAST(score, 10); -- Cap at 10
END;
$$ LANGUAGE plpgsql;

-- Function to update risk score
CREATE OR REPLACE FUNCTION update_risk_score() RETURNS TRIGGER AS $$
BEGIN
    -- Update risk score for the fingerprint
    UPDATE fingerprints 
    SET risk_score = calculate_risk_score(COALESCE(NEW.fingerprint_id, OLD.fingerprint_id)),
        updated_at = NOW()
    WHERE id = COALESCE(NEW.fingerprint_id, OLD.fingerprint_id);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Function to check rate limits
CREATE OR REPLACE FUNCTION check_rate_limit(
    fingerprint_uuid UUID,
    action_type_param VARCHAR(50),
    max_attempts INTEGER DEFAULT 10,
    window_minutes INTEGER DEFAULT 60
) RETURNS BOOLEAN AS $$
DECLARE
    current_attempts INTEGER;
BEGIN
    -- Clean old entries
    DELETE FROM rate_limits 
    WHERE fingerprint_id = fingerprint_uuid 
    AND action_type = action_type_param
    AND window_start < NOW() - INTERVAL '1 minute' * window_minutes;
    
    -- Count current attempts
    SELECT COALESCE(SUM(attempts), 0) INTO current_attempts
    FROM rate_limits 
    WHERE fingerprint_id = fingerprint_uuid 
    AND action_type = action_type_param
    AND window_start >= NOW() - INTERVAL '1 minute' * window_minutes;
    
    -- Check if limit exceeded
    IF current_attempts >= max_attempts THEN
        RETURN FALSE;
    END IF;
    
    -- Record this attempt
    INSERT INTO rate_limits (fingerprint_id, action_type, attempts)
    VALUES (fingerprint_uuid, action_type_param, 1)
    ON CONFLICT (fingerprint_id, action_type) 
    DO UPDATE SET 
        attempts = rate_limits.attempts + 1,
        window_start = CASE 
            WHEN rate_limits.window_start < NOW() - INTERVAL '1 minute' * window_minutes 
            THEN NOW() 
            ELSE rate_limits.window_start 
        END;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function to log admin actions
CREATE OR REPLACE FUNCTION log_admin_action(
    admin_uuid UUID,
    action_name VARCHAR(100),
    target_type_param VARCHAR(50) DEFAULT NULL,
    target_uuid UUID DEFAULT NULL,
    details_json JSONB DEFAULT NULL,
    ip_addr INET DEFAULT NULL,
    user_agent_text TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    log_id UUID;
BEGIN
    INSERT INTO admin_logs (
        admin_id, action, target_type, target_id, details, ip_address, user_agent
    ) VALUES (
        admin_uuid, action_name, target_type_param, target_uuid, details_json, ip_addr, user_agent_text
    ) RETURNING id INTO log_id;
    
    RETURN log_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get dashboard statistics (updated after all tables are created)
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

-- Function to detect bot signals
CREATE OR REPLACE FUNCTION detect_bot_signals(fingerprint_uuid UUID) RETURNS JSONB AS $$
DECLARE
    device_info JSONB;
    bot_signals JSONB := '[]'::jsonb;
    signal_count INTEGER := 0;
BEGIN
    SELECT device_info INTO device_info FROM fingerprints WHERE id = fingerprint_uuid;
    
    IF device_info IS NULL THEN
        RETURN jsonb_build_object('signals', '[]', 'count', 0, 'score', 0);
    END IF;
    
    -- Check for automation signals
    IF (device_info->>'webdriver')::boolean THEN
        bot_signals := bot_signals || '["webdriver"]'::jsonb;
        signal_count := signal_count + 3;
    END IF;
    
    IF (device_info->>'phantom')::boolean THEN
        bot_signals := bot_signals || '["phantom"]'::jsonb;
        signal_count := signal_count + 3;
    END IF;
    
    IF (device_info->>'selenium')::boolean THEN
        bot_signals := bot_signals || '["selenium"]'::jsonb;
        signal_count := signal_count + 3;
    END IF;
    
    IF (device_info->>'headless')::boolean THEN
        bot_signals := bot_signals || '["headless"]'::jsonb;
        signal_count := signal_count + 2;
    END IF;
    
    IF (device_info->>'automation')::boolean THEN
        bot_signals := bot_signals || '["automation"]'::jsonb;
        signal_count := signal_count + 2;
    END IF;
    
    -- Check for missing hardware info
    IF COALESCE((device_info->>'hardwareConcurrency')::integer, 0) = 0 THEN
        bot_signals := bot_signals || '["no_cpu_cores"]'::jsonb;
        signal_count := signal_count + 1;
    END IF;
    
    IF COALESCE((device_info->>'deviceMemory')::integer, 0) = 0 THEN
        bot_signals := bot_signals || '["no_memory_info"]'::jsonb;
        signal_count := signal_count + 1;
    END IF;
    
    RETURN jsonb_build_object(
        'signals', bot_signals,
        'count', signal_count,
        'score', LEAST(signal_count, 10)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to update ML anomaly score
CREATE OR REPLACE FUNCTION update_ml_anomaly_score(fingerprint_uuid UUID, anomaly_score DECIMAL, confidence DECIMAL, explanation TEXT) RETURNS VOID AS $$
BEGIN
    UPDATE fingerprints 
    SET ml_anomaly_score = anomaly_score,
        confidence_score = confidence,
        updated_at = NOW()
    WHERE id = fingerprint_uuid;
    
    -- Log ML analysis result
    INSERT INTO ml_analysis_results (
        fingerprint_id, 
        model_name, 
        model_version, 
        anomaly_score, 
        confidence, 
        explanation, 
        is_anomaly
    ) VALUES (
        fingerprint_uuid,
        'anomaly_detector',
        '1.0',
        anomaly_score,
        confidence,
        explanation,
        anomaly_score > 0.5
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get fraud pattern analysis
CREATE OR REPLACE FUNCTION get_fraud_pattern_analysis(days_back INTEGER DEFAULT 7) RETURNS JSONB AS $$
DECLARE
    analysis JSONB;
    patterns JSONB;
BEGIN
    SELECT jsonb_object_agg(
        risk_type,
        jsonb_build_object(
            'count', count,
            'avg_severity', avg_severity,
            'max_severity', max_severity,
            'last_occurrence', last_occurrence
        )
    ) INTO patterns
    FROM (
        SELECT 
            risk_type,
            COUNT(*) as count,
            AVG(severity) as avg_severity,
            MAX(severity) as max_severity,
            MAX(created_at) as last_occurrence
        FROM risk_logs 
        WHERE created_at > NOW() - INTERVAL '1 day' * days_back
        GROUP BY risk_type
    ) pattern_stats;
    
    SELECT jsonb_build_object(
        'patterns', COALESCE(patterns, '{}'::jsonb),
        'total_events', (SELECT COUNT(*) FROM risk_logs WHERE created_at > NOW() - INTERVAL '1 day' * days_back),
        'high_severity_events', (SELECT COUNT(*) FROM risk_logs WHERE created_at > NOW() - INTERVAL '1 day' * days_back AND severity >= 4),
        'analysis_period_days', days_back
    ) INTO analysis;
    
    RETURN analysis;
END;
$$ LANGUAGE plpgsql;

-- Triggers to automatically update risk scores
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

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_fingerprints_updated_at ON fingerprints;
CREATE TRIGGER trigger_update_fingerprints_updated_at
    BEFORE UPDATE ON fingerprints
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_update_users_updated_at ON users;
CREATE TRIGGER trigger_update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_update_fraud_patterns_updated_at ON fraud_patterns;
CREATE TRIGGER trigger_update_fraud_patterns_updated_at
    BEFORE UPDATE ON fraud_patterns
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger to update last_activity on fingerprint
CREATE OR REPLACE FUNCTION update_fingerprint_last_activity() RETURNS TRIGGER AS $$
BEGIN
    UPDATE fingerprints 
    SET last_activity = NOW()
    WHERE id = NEW.fingerprint_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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

-- Trigger to update URL click count and last clicked
CREATE OR REPLACE FUNCTION update_url_stats() RETURNS TRIGGER AS $$
BEGIN
    UPDATE urls 
    SET click_count = click_count + 1,
        last_clicked_at = NOW()
    WHERE id = NEW.url_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_url_stats ON url_visits;
CREATE TRIGGER trigger_update_url_stats
    AFTER INSERT ON url_visits
    FOR EACH ROW
    EXECUTE FUNCTION update_url_stats();

-- Row Level Security (RLS) Policies

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_visits ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fraud_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Policies for public access (URL shortening and visiting)
DROP POLICY IF EXISTS "Allow public URL creation" ON urls;
CREATE POLICY "Allow public URL creation" ON urls
    FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public URL reading" ON urls;
CREATE POLICY "Allow public URL reading" ON urls
    FOR SELECT USING (is_active = TRUE);

DROP POLICY IF EXISTS "Allow public URL updates for click count" ON urls;
CREATE POLICY "Allow public URL updates for click count" ON urls
    FOR UPDATE USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public fingerprint creation" ON fingerprints;
CREATE POLICY "Allow public fingerprint creation" ON fingerprints
    FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public fingerprint reading" ON fingerprints;
CREATE POLICY "Allow public fingerprint reading" ON fingerprints
    FOR SELECT USING (true);

DROP POLICY IF EXISTS "Allow public visit logging" ON url_visits;
CREATE POLICY "Allow public visit logging" ON url_visits
    FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public rate limit tracking" ON rate_limits;
CREATE POLICY "Allow public rate limit tracking" ON rate_limits
    FOR ALL USING (true);

-- Admin policies (require authentication)
DROP POLICY IF EXISTS "Admin can view all URLs" ON urls;
CREATE POLICY "Admin can view all URLs" ON urls
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can manage URLs" ON urls;
CREATE POLICY "Admin can manage URLs" ON urls
    FOR ALL USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can view all fingerprints" ON fingerprints;
CREATE POLICY "Admin can view all fingerprints" ON fingerprints
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can manage fingerprints" ON fingerprints;
CREATE POLICY "Admin can manage fingerprints" ON fingerprints
    FOR ALL USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can view all visits" ON url_visits;
CREATE POLICY "Admin can view all visits" ON url_visits
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can view all risk logs" ON risk_logs;
CREATE POLICY "Admin can view all risk logs" ON risk_logs
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can manage risk logs" ON risk_logs;
CREATE POLICY "Admin can manage risk logs" ON risk_logs
    FOR ALL USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can view all admin logs" ON admin_logs;
CREATE POLICY "Admin can view all admin logs" ON admin_logs
    FOR SELECT USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Admin can create admin logs" ON admin_logs;
CREATE POLICY "Admin can create admin logs" ON admin_logs
    FOR INSERT WITH CHECK (auth.role() = 'authenticated');

-- Policies for new tables
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

-- User policies
DROP POLICY IF EXISTS "Users can view own data" ON users;
CREATE POLICY "Users can view own data" ON users
    FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update own data" ON users;
CREATE POLICY "Users can update own data" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Views for easier querying (created after all tables)
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

-- Sample fraud patterns for testing
INSERT INTO fraud_patterns (pattern_name, pattern_type, description, severity_weight, detection_rules) VALUES
('duplicate_fingerprint', 'device_reuse', 'Same fingerprint used across multiple accounts', 4.0, '{"threshold": 1, "time_window": "24h"}'),
('high_velocity', 'behavior', 'Rapid URL creation pattern', 3.0, '{"threshold": 10, "time_window": "1h"}'),
('bot_detection', 'automation', 'Automation tools detected', 5.0, '{"signals": ["webdriver", "selenium", "phantom"]}'),
('click_fraud', 'behavior', 'Suspicious click patterns', 3.5, '{"threshold": 50, "time_window": "1h"}'),
('device_anomaly', 'device', 'Unusual device characteristics', 2.5, '{"checks": ["resolution", "hardware", "capabilities"]}')
ON CONFLICT (pattern_name) DO NOTHING;

-- Sample data for testing (optional)
INSERT INTO fingerprints (visitor_id, browser_info, device_info, user_agent, risk_score, ml_anomaly_score) VALUES
('test_visitor_1', '{"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "language": "en-US"}', '{"screen": {"width": 1920, "height": 1080}, "hardwareConcurrency": 8, "deviceMemory": 8}', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 0, 0.1),
('test_visitor_2', '{"userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "language": "en-US"}', '{"screen": {"width": 1920, "height": 1080}, "hardwareConcurrency": 0, "deviceMemory": 0, "webdriver": true}', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 7, 0.8)
ON CONFLICT (visitor_id) DO NOTHING;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated;

-- Comments for documentation
COMMENT ON TABLE fingerprints IS 'Stores device fingerprints with enhanced fraud detection fields including ML anomaly scores';
COMMENT ON TABLE urls IS 'Stores shortened URLs with enhanced tracking and analytics';
COMMENT ON TABLE url_visits IS 'Tracks every URL visit with comprehensive device and behavioral information';
COMMENT ON TABLE risk_logs IS 'Logs suspicious activities and fraud attempts with detailed pattern tracking';
COMMENT ON TABLE rate_limits IS 'Implements rate limiting per fingerprint with configurable windows';
COMMENT ON TABLE admin_logs IS 'Audit trail for admin actions and system changes';
COMMENT ON TABLE fraud_patterns IS 'Defines fraud detection patterns and their severity weights';
COMMENT ON TABLE ml_analysis_results IS 'Stores ML-based anomaly detection results and explanations';
COMMENT ON TABLE sessions IS 'Tracks user sessions for behavioral analysis';

COMMENT ON FUNCTION generate_short_code() IS 'Generates unique 6-character short codes with collision detection';
COMMENT ON FUNCTION calculate_risk_score(UUID) IS 'Calculates comprehensive risk score for a fingerprint using multiple factors';
COMMENT ON FUNCTION check_rate_limit(UUID, VARCHAR, INTEGER, INTEGER) IS 'Checks if fingerprint is within rate limits with automatic cleanup';
COMMENT ON FUNCTION get_dashboard_stats() IS 'Returns comprehensive dashboard statistics including ML anomalies and bot detections';
COMMENT ON FUNCTION detect_bot_signals(UUID) IS 'Detects automation and bot signals from device fingerprint';
COMMENT ON FUNCTION update_ml_anomaly_score(UUID, DECIMAL, DECIMAL, TEXT) IS 'Updates ML anomaly score and logs analysis results';
COMMENT ON FUNCTION get_fraud_pattern_analysis(INTEGER) IS 'Analyzes fraud patterns over specified time period';
