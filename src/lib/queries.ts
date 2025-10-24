// Example queries for checking fingerprint risk and logging URL visits

import { supabase } from './supabase'

// Query examples for fraud detection and monitoring

export const exampleQueries = {
  // Get high-risk fingerprints
  getHighRiskFingerprints: async (minRiskScore: number = 5) => {
    const { data, error } = await supabase
      .from('fingerprints')
      .select(`
        *,
        urls (
          id,
          original_url,
          short_code,
          created_at
        ),
        url_visits (
          id,
          visited_at
        ),
        risk_logs (
          id,
          risk_type,
          severity,
          created_at
        )
      `)
      .gte('risk_score', minRiskScore)
      .order('risk_score', { ascending: false })

    if (error) {
      console.error('Error fetching high-risk fingerprints:', error)
      return []
    }

    return data
  },

  // Get suspicious URL patterns
  getSuspiciousUrls: async () => {
    const { data, error } = await supabase
      .from('urls')
      .select(`
        *,
        fingerprints (
          visitor_id,
          risk_score,
          browser_info
        )
      `)
      .or('original_url.like.%bit.ly%,original_url.like.%tinyurl%,original_url.like.%short.link%')
      .order('created_at', { ascending: false })

    if (error) {
      console.error('Error fetching suspicious URLs:', error)
      return []
    }

    return data
  },

  // Get recent risk events
  getRecentRiskEvents: async (hours: number = 24) => {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
    
    const { data, error } = await supabase
      .from('risk_logs')
      .select(`
        *,
        fingerprints (
          visitor_id,
          risk_score,
          browser_info
        )
      `)
      .gte('created_at', since)
      .order('created_at', { ascending: false })

    if (error) {
      console.error('Error fetching recent risk events:', error)
      return []
    }

    return data
  },

  // Get URL visit analytics
  getUrlAnalytics: async (urlId: string) => {
    const { data, error } = await supabase
      .from('url_visits')
      .select(`
        *,
        fingerprints (
          visitor_id,
          risk_score,
          browser_info
        )
      `)
      .eq('url_id', urlId)
      .order('visited_at', { ascending: false })

    if (error) {
      console.error('Error fetching URL analytics:', error)
      return []
    }

    return data
  },

  // Get device activity summary
  getDeviceActivity: async (fingerprintId: string) => {
    const { data, error } = await supabase
      .from('fingerprints')
      .select(`
        *,
        urls (
          id,
          original_url,
          short_code,
          click_count,
          created_at
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
      .eq('id', fingerprintId)
      .single()

    if (error) {
      console.error('Error fetching device activity:', error)
      return null
    }

    return data
  },

  // Get dashboard statistics
  getDashboardStats: async () => {
    const [
      urlsResult,
      visitsResult,
      fingerprintsResult,
      riskLogsResult
    ] = await Promise.all([
      supabase.from('urls').select('id', { count: 'exact' }),
      supabase.from('url_visits').select('id', { count: 'exact' }),
      supabase.from('fingerprints').select('id', { count: 'exact' }),
      supabase.from('risk_logs').select('id', { count: 'exact' })
    ])

    const [
      highRiskResult,
      recentUrlsResult,
      recentVisitsResult
    ] = await Promise.all([
      supabase.from('fingerprints').select('id', { count: 'exact' }).gte('risk_score', 5),
      supabase.from('urls').select('id', { count: 'exact' }).gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()),
      supabase.from('url_visits').select('id', { count: 'exact' }).gte('visited_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
    ])

    return {
      totalUrls: urlsResult.count || 0,
      totalVisits: visitsResult.count || 0,
      totalFingerprints: fingerprintsResult.count || 0,
      totalRiskLogs: riskLogsResult.count || 0,
      highRiskFingerprints: highRiskResult.count || 0,
      recentUrls: recentUrlsResult.count || 0,
      recentVisits: recentVisitsResult.count || 0
    }
  },

  // Get top performing URLs
  getTopUrls: async (limit: number = 10) => {
    const { data, error } = await supabase
      .from('urls')
      .select(`
        *,
        fingerprints (
          visitor_id,
          risk_score
        )
      `)
      .order('click_count', { ascending: false })
      .limit(limit)

    if (error) {
      console.error('Error fetching top URLs:', error)
      return []
    }

    return data
  },

  // Get fraud patterns analysis
  getFraudPatterns: async () => {
    const { data, error } = await supabase
      .from('risk_logs')
      .select('risk_type, severity, created_at')
      .gte('created_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString())

    if (error) {
      console.error('Error fetching fraud patterns:', error)
      return []
    }

    // Group by risk type and calculate statistics
    const patterns = data.reduce((acc: any, log: any) => {
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
    }, {} as Record<string, any>)

    return patterns
  }
}

// Real-time subscription examples
export const realtimeSubscriptions = {
  // Subscribe to new URLs
  subscribeToNewUrls: (callback: (payload: any) => void) => {
    return supabase
      .channel('urls')
      .on('postgres_changes', 
        { event: 'INSERT', schema: 'public', table: 'urls' },
        callback
      )
      .subscribe()
  },

  // Subscribe to new visits
  subscribeToNewVisits: (callback: (payload: any) => void) => {
    return supabase
      .channel('visits')
      .on('postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'url_visits' },
        callback
      )
      .subscribe()
  },

  // Subscribe to risk events
  subscribeToRiskEvents: (callback: (payload: any) => void) => {
    return supabase
      .channel('risk_logs')
      .on('postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'risk_logs' },
        callback
      )
      .subscribe()
  },

  // Subscribe to fingerprint updates
  subscribeToFingerprintUpdates: (callback: (payload: any) => void) => {
    return supabase
      .channel('fingerprints')
      .on('postgres_changes',
        { event: 'UPDATE', schema: 'public', table: 'fingerprints' },
        callback
      )
      .subscribe()
  }
}

// Utility functions for data processing
export const dataProcessing = {
  // Calculate click-through rate
  calculateCTR: (clicks: number, impressions: number): number => {
    if (impressions === 0) return 0
    return (clicks / impressions) * 100
  },

  // Group data by time period
  groupByTimePeriod: (data: any[], period: 'hour' | 'day' | 'week' = 'day') => {
    const groups: Record<string, any[]> = {}
    
    data.forEach(item => {
      const date = new Date(item.created_at || item.visited_at)
      let key: string
      
      switch (period) {
        case 'hour':
          key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`
          break
        case 'week':
          const weekStart = new Date(date)
          weekStart.setDate(date.getDate() - date.getDay())
          key = weekStart.toISOString().split('T')[0]
          break
        default: // day
          key = date.toISOString().split('T')[0]
      }
      
      if (!groups[key]) groups[key] = []
      groups[key].push(item)
    })
    
    return groups
  },

  // Calculate risk score distribution
  calculateRiskDistribution: (fingerprints: any[]) => {
    const distribution = {
      low: 0,    // 0-2
      medium: 0, // 3-5
      high: 0,   // 6-8
      critical: 0 // 9-10
    }
    
    fingerprints.forEach(fp => {
      if (fp.risk_score <= 2) distribution.low++
      else if (fp.risk_score <= 5) distribution.medium++
      else if (fp.risk_score <= 8) distribution.high++
      else distribution.critical++
    })
    
    return distribution
  }
}
