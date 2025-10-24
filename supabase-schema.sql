-- Supabase Database Schema for URL Shortener with Fraud Detection

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (optional for user accounts)
CREATE TABLE users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Fingerprints table to store device fingerprints
CREATE TABLE fingerprints (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    visitor_id VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    browser_info JSONB,
    device_info JSONB,
    user_agent TEXT,
    risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- URLs table to store shortened URLs
CREATE TABLE urls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_url TEXT NOT NULL,
    short_code VARCHAR(10) UNIQUE NOT NULL,
    created_by UUID REFERENCES users(id),
    fingerprint_id UUID REFERENCES fingerprints(id),
    click_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- URL visits table to track every click
CREATE TABLE url_visits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url_id UUID REFERENCES urls(id) ON DELETE CASCADE,
    fingerprint_id UUID REFERENCES fingerprints(id),
    ip_address INET,
    referrer TEXT,
    user_agent TEXT,
    visited_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Risk logs table for suspicious activity
CREATE TABLE risk_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fingerprint_id UUID REFERENCES fingerprints(id),
    risk_type VARCHAR(50) NOT NULL, -- 'duplicate_fingerprint', 'multiple_accounts', 'spam_attempt', 'suspicious_pattern'
    description TEXT,
    severity INTEGER DEFAULT 1, -- 1-5 scale
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting table
CREATE TABLE rate_limits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fingerprint_id UUID REFERENCES fingerprints(id),
    action_type VARCHAR(50) NOT NULL, -- 'url_creation', 'admin_access'
    attempts INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for better performance
CREATE INDEX idx_fingerprints_visitor_id ON fingerprints(visitor_id);
CREATE INDEX idx_fingerprints_risk_score ON fingerprints(risk_score);
CREATE INDEX idx_urls_short_code ON urls(short_code);
CREATE INDEX idx_urls_created_at ON urls(created_at);
CREATE INDEX idx_url_visits_url_id ON url_visits(url_id);
CREATE INDEX idx_url_visits_visited_at ON url_visits(visited_at);
CREATE INDEX idx_risk_logs_fingerprint_id ON risk_logs(fingerprint_id);
CREATE INDEX idx_risk_logs_created_at ON risk_logs(created_at);
CREATE INDEX idx_rate_limits_fingerprint_action ON rate_limits(fingerprint_id, action_type);

-- Function to generate short codes
CREATE OR REPLACE FUNCTION generate_short_code() RETURNS TEXT AS $$
DECLARE
    chars TEXT := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    result TEXT := '';
    i INTEGER;
BEGIN
    FOR i IN 1..6 LOOP
        result := result || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
    END LOOP;
    
    -- Check if code already exists
    IF EXISTS (SELECT 1 FROM urls WHERE short_code = result) THEN
        RETURN generate_short_code();
    END IF;
    
    RETURN result;
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
BEGIN
    -- Count URLs created by this fingerprint
    SELECT COUNT(*) INTO url_count FROM urls WHERE fingerprint_id = fingerprint_uuid;
    IF url_count > 10 THEN
        score := score + 2;
    ELSIF url_count > 5 THEN
        score := score + 1;
    END IF;
    
    -- Count total visits from this fingerprint
    SELECT COUNT(*) INTO visit_count FROM url_visits WHERE fingerprint_id = fingerprint_uuid;
    IF visit_count > 100 THEN
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
        score := score + 3;
    END IF;
    
    RETURN LEAST(score, 10); -- Cap at 10
END;
$$ LANGUAGE plpgsql;

-- Function to update risk score
CREATE OR REPLACE FUNCTION update_risk_score() RETURNS TRIGGER AS $$
BEGIN
    UPDATE fingerprints 
    SET risk_score = calculate_risk_score(NEW.fingerprint_id),
        updated_at = NOW()
    WHERE id = NEW.fingerprint_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers to automatically update risk scores
CREATE TRIGGER trigger_update_risk_score_urls
    AFTER INSERT ON urls
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

CREATE TRIGGER trigger_update_risk_score_visits
    AFTER INSERT ON url_visits
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

CREATE TRIGGER trigger_update_risk_score_logs
    AFTER INSERT ON risk_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_score();

-- Row Level Security (RLS) Policies

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_visits ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- Policies for public access (URL shortening and visiting)
CREATE POLICY "Allow public URL creation" ON urls
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public URL reading" ON urls
    FOR SELECT USING (true);

CREATE POLICY "Allow public fingerprint creation" ON fingerprints
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public fingerprint reading" ON fingerprints
    FOR SELECT USING (true);

CREATE POLICY "Allow public visit logging" ON url_visits
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public rate limit tracking" ON rate_limits
    FOR ALL USING (true);

-- Admin policies (require authentication)
CREATE POLICY "Admin can view all data" ON urls
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can view all fingerprints" ON fingerprints
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can view all visits" ON url_visits
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can view all risk logs" ON risk_logs
    FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Admin can manage risk logs" ON risk_logs
    FOR ALL USING (auth.role() = 'authenticated');

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
