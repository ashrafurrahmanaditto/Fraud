// supabase/functions/check-fingerprint-risk/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
    )

    const { fingerprint_id, visitor_id } = await req.json()

    if (!fingerprint_id && !visitor_id) {
      return new Response(
        JSON.stringify({ error: 'Fingerprint ID or Visitor ID is required' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get fingerprint data
    let fingerprintQuery = supabaseClient
      .from('fingerprints')
      .select(`
        *,
        urls (
          id,
          original_url,
          short_code,
          created_at,
          click_count
        ),
        url_visits (
          id,
          visited_at,
          referrer
        ),
        risk_logs (
          id,
          risk_type,
          severity,
          description,
          created_at
        )
      `)

    if (fingerprint_id) {
      fingerprintQuery = fingerprintQuery.eq('id', fingerprint_id)
    } else {
      fingerprintQuery = fingerprintQuery.eq('visitor_id', visitor_id)
    }

    const { data: fingerprint, error } = await fingerprintQuery.single()

    if (error || !fingerprint) {
      return new Response(
        JSON.stringify({ error: 'Fingerprint not found' }),
        { 
          status: 404, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Calculate comprehensive risk score
    const { data: riskScore } = await supabaseClient.rpc('calculate_risk_score', {
      fingerprint_uuid: fingerprint.id
    })

    // Get recent activity patterns
    const { data: recentUrls } = await supabaseClient
      .from('urls')
      .select('created_at')
      .eq('fingerprint_id', fingerprint.id)
      .gte('created_at', new Date(Date.now() - 60 * 60 * 1000).toISOString()) // Last hour

    const { data: recentVisits } = await supabaseClient
      .from('url_visits')
      .select('visited_at')
      .eq('fingerprint_id', fingerprint.id)
      .gte('visited_at', new Date(Date.now() - 60 * 60 * 1000).toISOString()) // Last hour

    const { data: recentRiskLogs } = await supabaseClient
      .from('risk_logs')
      .select('*')
      .eq('fingerprint_id', fingerprint.id)
      .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()) // Last 24 hours

    // Analyze patterns
    const patterns = {
      urlCreationVelocity: recentUrls?.length || 0,
      visitVelocity: recentVisits?.length || 0,
      recentRiskEvents: recentRiskLogs?.length || 0,
      totalUrls: fingerprint.urls?.length || 0,
      totalVisits: fingerprint.url_visits?.length || 0,
      totalRiskLogs: fingerprint.risk_logs?.length || 0
    }

    // Determine risk level
    let riskLevel = 'low'
    if (riskScore >= 7) riskLevel = 'critical'
    else if (riskScore >= 5) riskLevel = 'high'
    else if (riskScore >= 3) riskLevel = 'medium'

    // Generate risk reasons
    const riskReasons = []
    if (patterns.urlCreationVelocity > 10) {
      riskReasons.push(`High URL creation velocity: ${patterns.urlCreationVelocity}/hour`)
    }
    if (patterns.visitVelocity > 50) {
      riskReasons.push(`High visit velocity: ${patterns.visitVelocity}/hour`)
    }
    if (patterns.recentRiskEvents > 0) {
      riskReasons.push(`${patterns.recentRiskEvents} recent risk events`)
    }
    if (patterns.totalUrls > 20) {
      riskReasons.push(`High total URL count: ${patterns.totalUrls}`)
    }

    const response = {
      fingerprint_id: fingerprint.id,
      visitor_id: fingerprint.visitor_id,
      risk_score: riskScore || 0,
      risk_level: riskLevel,
      risk_reasons: riskReasons,
      patterns: patterns,
      device_info: {
        user_agent: fingerprint.user_agent,
        browser_info: fingerprint.browser_info,
        device_info: fingerprint.device_info
      },
      activity_summary: {
        total_urls: patterns.totalUrls,
        total_visits: patterns.totalVisits,
        total_risk_logs: patterns.totalRiskLogs,
        created_at: fingerprint.created_at,
        last_updated: fingerprint.updated_at
      },
      recent_activity: {
        urls_last_hour: patterns.urlCreationVelocity,
        visits_last_hour: patterns.visitVelocity,
        risk_events_last_24h: patterns.recentRiskEvents
      }
    }

    return new Response(
      JSON.stringify(response),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('Error in check-fingerprint-risk function:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})
