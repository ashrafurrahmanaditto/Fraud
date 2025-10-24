// Supabase configuration
import { createClient } from '@supabase/supabase-js'

// Get environment variables with fallbacks
const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || 'https://otapspwjastqphsicqpg.supabase.co'
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im90YXBzcHdqYXN0cXBoc2ljcXBnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjEyOTcxNTUsImV4cCI6MjA3Njg3MzE1NX0.2i8hKlw2AjKkoEZ5VUPj_DmdlttdgX92M7hVyQNho0s'

// Debug environment variables
console.log('Environment REACT_APP_SUPABASE_URL:', process.env.REACT_APP_SUPABASE_URL)
console.log('Using Supabase URL:', supabaseUrl)
console.log('Environment REACT_APP_SUPABASE_ANON_KEY:', process.env.REACT_APP_SUPABASE_ANON_KEY ? 'Present' : 'Missing')
console.log('Using Supabase Key:', supabaseAnonKey ? 'Present' : 'Missing')

// Validate URL format
if (!supabaseUrl.startsWith('http://') && !supabaseUrl.startsWith('https://')) {
  console.error('Invalid Supabase URL format:', supabaseUrl)
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey) as any

// Test Supabase connection
(async () => {
  try {
    const { data, error } = await supabase.from('fingerprints').select('count').limit(1)
    if (error) {
      console.error('❌ Supabase connection test failed:', error)
    } else {
      console.log('✅ Supabase connection test successful:', data)
    }
  } catch (err) {
    console.error('❌ Supabase connection error:', err)
  }
})()

// Database types
export interface Fingerprint {
  id: string
  visitor_id: string
  ip_address?: string
  browser_info?: any
  device_info?: any
  user_agent?: string
  risk_score: number
  created_at: string
  updated_at: string
}

export interface Url {
  id: string
  original_url: string
  short_code: string
  created_by?: string
  fingerprint_id?: string
  click_count: number
  created_at: string
  expires_at?: string
}

export interface UrlVisit {
  id: string
  url_id: string
  fingerprint_id?: string
  ip_address?: string
  referrer?: string
  user_agent?: string
  visited_at: string
}

export interface RiskLog {
  id: string
  fingerprint_id?: string
  risk_type: string
  description?: string
  severity: number
  metadata?: any
  created_at: string
}

export interface RateLimit {
  id: string
  fingerprint_id?: string
  action_type: string
  attempts: number
  window_start: string
  created_at: string
}
