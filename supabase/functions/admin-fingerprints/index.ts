// supabase/functions/admin-fingerprints/index.ts
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

    // Verify admin access (you may want to implement proper admin authentication)
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Authorization required' }),
        { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const url = new URL(req.url)
    const limit = parseInt(url.searchParams.get('limit') || '50')
    const offset = parseInt(url.searchParams.get('offset') || '0')
    const riskThreshold = parseInt(url.searchParams.get('risk_threshold') || '5')
    const sortBy = url.searchParams.get('sort_by') || 'risk_score'
    const sortOrder = url.searchParams.get('sort_order') || 'desc'

    // Get high-risk fingerprints with detailed information
    const { data: fingerprints, error } = await supabaseClient
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
          referrer,
          country,
          city
        ),
        risk_logs (
          id,
          risk_type,
          severity,
          description,
          metadata,
          created_at
        )
      `)
      .gte('risk_score', riskThreshold)
      .order(sortBy, { ascending: sortOrder === 'asc' })
      .range(offset, offset + limit - 1)

    if (error) {
      console.error('Error fetching fingerprints:', error)
      return new Response(
        JSON.stringify({ error: 'Failed to fetch fingerprints' }),
        { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get dashboard statistics
    const { data: stats } = await supabaseClient.rpc('get_dashboard_stats')

    // Process fingerprints for admin display
    const processedFingerprints = fingerprints?.map(fp => ({
      id: fp.id,
      visitor_id: fp.visitor_id,
      risk_score: fp.risk_score,
      created_at: fp.created_at,
      updated_at: fp.updated_at,
      user_agent: fp.user_agent,
      ip_address: fp.ip_address,
      browser_info: fp.browser_info,
      device_info: fp.device_info,
      activity_summary: {
        total_urls: fp.urls?.length || 0,
        total_visits: fp.url_visits?.length || 0,
        total_risk_logs: fp.risk_logs?.length || 0,
        last_activity: fp.url_visits?.[0]?.visited_at || fp.created_at
      },
      recent_urls: fp.urls?.slice(0, 5).map(url => ({
        id: url.id,
        original_url: url.original_url,
        short_code: url.short_code,
        created_at: url.created_at,
        click_count: url.click_count
      })) || [],
      recent_risk_logs: fp.risk_logs?.slice(0, 5).map(log => ({
        id: log.id,
        risk_type: log.risk_type,
        severity: log.severity,
        description: log.description,
        created_at: log.created_at
      })) || [],
      risk_patterns: fp.risk_logs?.map(log => log.risk_type) || [],
      // Extract key device characteristics for analysis
      device_characteristics: {
        is_mobile: fp.device_info?.mobile || false,
        has_touch: fp.device_info?.touchSupport || false,
        hardware_concurrency: fp.device_info?.hardwareConcurrency || 0,
        device_memory: fp.device_info?.deviceMemory || 0,
        screen_resolution: fp.device_info?.screenResolution || 'unknown',
        timezone: fp.device_info?.timezone || 'unknown',
        language: fp.device_info?.language || 'unknown',
        platform: fp.device_info?.platform || 'unknown',
        // Bot detection signals
        webdriver: fp.device_info?.webdriver || false,
        phantom: fp.device_info?.phantom || false,
        selenium: fp.device_info?.selenium || false,
        headless: fp.device_info?.headless || false,
        automation: fp.device_info?.automation || false
      }
    })) || []

    // Get fraud patterns analysis
    const { data: fraudPatterns } = await supabaseClient
      .from('risk_logs')
      .select('risk_type, severity, created_at')
      .gte('created_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString())

    const patternAnalysis = fraudPatterns?.reduce((acc, log) => {
      if (!acc[log.risk_type]) {
        acc[log.risk_type] = {
          count: 0,
          totalSeverity: 0,
          avgSeverity: 0,
          lastOccurrence: log.created_at
        }
      }
      acc[log.risk_type].count++
      acc[log.risk_type].totalSeverity += log.severity
      acc[log.risk_type].avgSeverity = acc[log.risk_type].totalSeverity / acc[log.risk_type].count
      if (new Date(log.created_at) > new Date(acc[log.risk_type].lastOccurrence)) {
        acc[log.risk_type].lastOccurrence = log.created_at
      }
      return acc
    }, {} as Record<string, any>) || {}

    const response = {
      fingerprints: processedFingerprints,
      pagination: {
        limit,
        offset,
        total: processedFingerprints.length,
        has_more: processedFingerprints.length === limit
      },
      statistics: stats,
      fraud_patterns: patternAnalysis,
      filters: {
        risk_threshold: riskThreshold,
        sort_by: sortBy,
        sort_order: sortOrder
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
    console.error('Error in admin-fingerprints function:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})
