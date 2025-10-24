import React, { useState, useEffect } from 'react'
import { supabase, Url, Fingerprint, UrlVisit, RiskLog } from '../lib/supabase'
import { detectFraud, detectMLAnomalies } from '../lib/advancedFraudDetection'
import toast from 'react-hot-toast'

interface DashboardStats {
  totalUrls: number
  totalVisits: number
  highRiskFingerprints: number
  recentRiskLogs: number
  mlAnomalies: number
  fraudPatterns: Record<string, any>
  realTimeAlerts: number
}

interface EnhancedFingerprint extends Fingerprint {
  device_characteristics?: {
    is_mobile: boolean
    has_touch: boolean
    hardware_concurrency: number
    device_memory: number
    screen_resolution: string
    webdriver: boolean
    phantom: boolean
    selenium: boolean
    headless: boolean
    automation: boolean
  }
  activity_summary?: {
    total_urls: number
    total_visits: number
    total_risk_logs: number
    last_activity: string
  }
  recent_risk_logs?: RiskLog[]
  ml_anomaly_score?: number
}

const AdminDashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalUrls: 0,
    totalVisits: 0,
    highRiskFingerprints: 0,
    recentRiskLogs: 0,
    mlAnomalies: 0,
    fraudPatterns: {},
    realTimeAlerts: 0
  })
  const [recentUrls, setRecentUrls] = useState<Url[]>([])
  const [highRiskFingerprints, setHighRiskFingerprints] = useState<EnhancedFingerprint[]>([])
  const [recentVisits, setRecentVisits] = useState<UrlVisit[]>([])
  const [riskLogs, setRiskLogs] = useState<RiskLog[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const [realTimeEnabled, setRealTimeEnabled] = useState(true)
  const [selectedFingerprint, setSelectedFingerprint] = useState<EnhancedFingerprint | null>(null)
  const [fraudAnalysis, setFraudAnalysis] = useState<any>(null)

  useEffect(() => {
    loadDashboardData()
    setupRealtimeSubscriptions()
  }, [])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      console.log('📊 Loading dashboard data...')

      // Load comprehensive stats using dashboard function
      let dashboardStats: any = null
      const { data: statsData, error: statsError } = await supabase.rpc('get_dashboard_stats')
      
      if (statsError) {
        console.error('❌ Error with dashboard stats function:', statsError)
        // Fallback: get stats directly from database
        console.log('🔄 Falling back to direct database queries...')
        
        const [
          { count: totalUrls },
          { count: totalVisits },
          { count: highRiskFingerprints },
          { count: recentRiskLogs }
        ] = await Promise.all([
          supabase.from('urls').select('*', { count: 'exact', head: true }).eq('is_active', true),
          supabase.from('url_visits').select('*', { count: 'exact', head: true }),
          supabase.from('fingerprints').select('*', { count: 'exact', head: true }).gte('risk_score', 5),
          supabase.from('risk_logs').select('*', { count: 'exact', head: true }).gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
        ])
        
        console.log('📊 Direct stats:', { totalUrls, totalVisits, highRiskFingerprints, recentRiskLogs })
        
        // Use direct stats if dashboard function fails
        dashboardStats = {
          total_urls: totalUrls || 0,
          total_visits: totalVisits || 0,
          high_risk_fingerprints: highRiskFingerprints || 0,
          risk_events_24h: recentRiskLogs || 0,
          active_rate_limits: 0
        }
      } else {
        dashboardStats = statsData
        console.log('✅ Dashboard stats loaded:', dashboardStats)
      }
      
      // Load enhanced fingerprint data
      const { data: fingerprints } = await supabase
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
        .gte('risk_score', 5)
        .order('risk_score', { ascending: false })
        .limit(20)

      // Process fingerprints with enhanced data
      const enhancedFingerprints = await Promise.all(
        (fingerprints || []).map(async (fp: any) => {
          // Get ML anomaly score
          const mlResult = await detectMLAnomalies(fp.id)
          
          return {
            ...fp,
            device_characteristics: {
              is_mobile: fp.device_info?.mobile || false,
              has_touch: fp.device_info?.touchSupport || false,
              hardware_concurrency: fp.device_info?.hardwareConcurrency || 0,
              device_memory: fp.device_info?.deviceMemory || 0,
              screen_resolution: fp.device_info?.screenResolution || 'unknown',
              webdriver: fp.device_info?.webdriver || false,
              phantom: fp.device_info?.phantom || false,
              selenium: fp.device_info?.selenium || false,
              headless: fp.device_info?.headless || false,
              automation: fp.device_info?.automation || false
            },
            activity_summary: {
              total_urls: fp.urls?.length || 0,
              total_visits: fp.url_visits?.length || 0,
              total_risk_logs: fp.risk_logs?.length || 0,
              last_activity: fp.url_visits?.[0]?.visited_at || fp.created_at
            },
            ml_anomaly_score: mlResult.anomalyScore
          }
        })
      )

      // Get fraud patterns analysis
      const { data: fraudPatterns } = await supabase
        .from('risk_logs')
        .select('risk_type, severity, created_at')
        .gte('created_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString())

      const patternAnalysis = fraudPatterns?.reduce((acc: any, log: any) => {
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

      setStats({
        totalUrls: dashboardStats?.total_urls || 0,
        totalVisits: dashboardStats?.total_visits || 0,
        highRiskFingerprints: dashboardStats?.high_risk_fingerprints || 0,
        recentRiskLogs: dashboardStats?.risk_events_24h || 0,
        mlAnomalies: enhancedFingerprints.filter(fp => fp.ml_anomaly_score && fp.ml_anomaly_score > 0.5).length,
        fraudPatterns: patternAnalysis,
        realTimeAlerts: dashboardStats?.active_rate_limits || 0
      })

      // Load recent URLs
      const { data: urls } = await supabase
        .from('urls')
        .select(`
          *,
          fingerprints (
            visitor_id,
            risk_score,
            browser_info
          )
        `)
        .order('created_at', { ascending: false })
        .limit(10)

      setRecentUrls(urls || [])

      // Load high-risk fingerprints
      const { data: highRiskFingerprints } = await supabase
        .from('fingerprints')
        .select('*')
        .gte('risk_score', 5)
        .order('risk_score', { ascending: false })
        .limit(10)

      setHighRiskFingerprints(highRiskFingerprints || [])

      // Load recent visits
      const { data: visits, error: visitsError } = await supabase
        .from('url_visits')
        .select(`
          *,
          urls (
            original_url,
            short_code
          ),
          fingerprints (
            visitor_id,
            risk_score
          )
        `)
        .order('visited_at', { ascending: false })
        .limit(20)

      if (visitsError) {
        console.error('❌ Error loading recent visits:', visitsError)
        toast.error('Failed to load recent visits')
      } else {
        console.log('✅ Recent visits loaded:', visits?.length || 0, 'visits')
      }

      setRecentVisits(visits || [])

      // Load risk logs
      const { data: logs } = await supabase
        .from('risk_logs')
        .select(`
          *,
          fingerprints (
            visitor_id,
            risk_score
          )
        `)
        .order('created_at', { ascending: false })
        .limit(20)

      setRiskLogs(logs || [])

    } catch (error) {
      console.error('Error loading dashboard data:', error)
      toast.error('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const setupRealtimeSubscriptions = () => {
    if (!realTimeEnabled) return

    // Subscribe to new URLs
    supabase
      .channel('urls')
      .on('postgres_changes', 
        { event: 'INSERT', schema: 'public', table: 'urls' },
        (payload: any) => {
          toast.success('New URL created!')
          loadDashboardData()
        }
      )
      .subscribe()

    // Subscribe to new visits
    supabase
      .channel('visits')
      .on('postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'url_visits' },
        (payload: any) => {
          loadDashboardData()
        }
      )
      .subscribe()

    // Subscribe to risk logs
    supabase
      .channel('risk_logs')
      .on('postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'risk_logs' },
        (payload: any) => {
          toast.error('New risk event detected!')
          loadDashboardData()
        }
      )
      .subscribe()

    // Subscribe to fingerprint updates
    supabase
      .channel('fingerprints')
      .on('postgres_changes',
        { event: 'UPDATE', schema: 'public', table: 'fingerprints' },
        (payload: any) => {
          if (payload.new.risk_score > 5) {
            toast.error(`High-risk fingerprint updated: Score ${payload.new.risk_score}`)
          }
          loadDashboardData()
        }
      )
      .subscribe()
  }

  // Enhanced fraud analysis for selected fingerprint
  const analyzeFingerprint = async (fingerprint: EnhancedFingerprint) => {
    try {
      const fraudResult = await detectFraud(fingerprint.id)
      const mlResult = await detectMLAnomalies(fingerprint.id)
      
      setFraudAnalysis({
        fraudDetection: fraudResult,
        mlAnomaly: mlResult,
        fingerprint: fingerprint,
        timestamp: new Date().toISOString()
      })
      
      setSelectedFingerprint(fingerprint)
    } catch (error) {
      console.error('Error analyzing fingerprint:', error)
      toast.error('Failed to analyze fingerprint')
    }
  }

  // Get bot detection summary
  const getBotDetectionSummary = (fingerprint: EnhancedFingerprint) => {
    const characteristics = fingerprint.device_characteristics
    if (!characteristics) return { score: 0, signals: [] }

    const signals = []
    let score = 0

    if (characteristics.webdriver) {
      signals.push('WebDriver')
      score += 3
    }
    if (characteristics.phantom) {
      signals.push('PhantomJS')
      score += 3
    }
    if (characteristics.selenium) {
      signals.push('Selenium')
      score += 3
    }
    if (characteristics.headless) {
      signals.push('Headless')
      score += 2
    }
    if (characteristics.automation) {
      signals.push('Automation')
      score += 2
    }
    if (characteristics.hardware_concurrency === 0) {
      signals.push('No CPU cores')
      score += 1
    }
    if (characteristics.device_memory === 0) {
      signals.push('No memory info')
      score += 1
    }

    return { score, signals }
  }

  const getRiskColor = (score: number) => {
    if (score === 0) return 'text-green-600 bg-green-100'
    if (score <= 3) return 'text-yellow-600 bg-yellow-100'
    if (score <= 6) return 'text-orange-600 bg-orange-100'
    return 'text-red-600 bg-red-100'
  }

  const getSeverityColor = (severity: number) => {
    if (severity <= 2) return 'text-yellow-600 bg-yellow-100'
    if (severity <= 4) return 'text-orange-600 bg-orange-100'
    return 'text-red-600 bg-red-100'
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Admin Dashboard</h1>
          <p className="text-gray-600">Monitor URL shortening activity and fraud detection</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-lg">
                <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total URLs</p>
                <p className="text-2xl font-semibold text-gray-900">{stats.totalUrls}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-green-100 rounded-lg">
                <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Visits</p>
                <p className="text-2xl font-semibold text-gray-900">{stats.totalVisits}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-red-100 rounded-lg">
                <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">High Risk Devices</p>
                <p className="text-2xl font-semibold text-gray-900">{stats.highRiskFingerprints}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-yellow-100 rounded-lg">
                <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Risk Events (24h)</p>
                <p className="text-2xl font-semibold text-gray-900">{stats.recentRiskLogs}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white rounded-lg shadow">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              {[
                { id: 'overview', name: 'Overview' },
                { id: 'urls', name: 'Recent URLs' },
                { id: 'visits', name: 'Recent Visits' },
                { id: 'risks', name: 'Risk Events' },
                { id: 'devices', name: 'High Risk Devices' },
                { id: 'fraud', name: 'Fraud Analysis' },
                { id: 'patterns', name: 'Fraud Patterns' },
                { id: 'ml', name: 'ML Anomalies' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  {tab.name}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div>
                      <h4 className="font-medium text-gray-700 mb-2">Latest URLs</h4>
                      <div className="space-y-2">
                        {recentUrls.slice(0, 5).map((url) => (
                          <div key={url.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-gray-900 truncate">
                                {url.original_url}
                              </p>
                              <p className="text-xs text-gray-500">
                                {window.location.origin}/{url.short_code}
                              </p>
                            </div>
                            <span className={`px-2 py-1 text-xs rounded ${
                              url.fingerprint_id ? getRiskColor(0) : 'text-gray-600 bg-gray-100'
                            }`}>
                              {url.fingerprint_id ? 0 : 0}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-700 mb-2">Recent Risk Events</h4>
                      <div className="space-y-2">
                        {riskLogs.slice(0, 5).map((log) => (
                          <div key={log.id} className="p-2 bg-gray-50 rounded">
                            <div className="flex items-center justify-between">
                              <span className="text-sm font-medium text-gray-900">
                                {log.risk_type.replace('_', ' ')}
                              </span>
                              <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(log.severity)}`}>
                                {log.severity}
                              </span>
                            </div>
                            <p className="text-xs text-gray-500 mt-1">
                              {new Date(log.created_at).toLocaleString()}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* URLs Tab */}
            {activeTab === 'urls' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent URLs</h3>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Original URL
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Short Code
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Clicks
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Risk Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Created
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {recentUrls.map((url) => (
                        <tr key={url.id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900 max-w-xs truncate">
                              {url.original_url}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-mono text-blue-600">
                              {url.short_code}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {url.click_count}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-2 py-1 text-xs rounded ${
                              url.fingerprint_id ? getRiskColor(0) : 'text-gray-600 bg-gray-100'
                            }`}>
                              {url.fingerprint_id ? 0 : 0}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(url.created_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Visits Tab */}
            {activeTab === 'visits' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Visits</h3>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          URL
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Visitor ID
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Risk Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Visited At
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {recentVisits.map((visit) => (
                        <tr key={visit.id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900 max-w-xs truncate">
                              {visit.url_id ? 'URL ID: ' + visit.url_id : 'N/A'}
                            </div>
                            <div className="text-xs text-gray-500">
                              {visit.url_id ? 'Code: ' + visit.url_id.substring(0, 8) : 'N/A'}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-mono text-gray-900">
                              {visit.fingerprint_id ? visit.fingerprint_id.substring(0, 8) + '...' : 'N/A'}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-2 py-1 text-xs rounded ${
                              visit.fingerprint_id ? getRiskColor(0) : 'text-gray-600 bg-gray-100'
                            }`}>
                              {visit.fingerprint_id ? 0 : 0}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(visit.visited_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Risk Events Tab */}
            {activeTab === 'risks' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Events</h3>
                <div className="space-y-4">
                  {riskLogs.map((log) => (
                    <div key={log.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-medium text-gray-900 capitalize">
                          {log.risk_type.replace('_', ' ')}
                        </h4>
                        <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(log.severity)}`}>
                          Severity: {log.severity}
                        </span>
                      </div>
                      {log.description && (
                        <p className="text-sm text-gray-600 mb-2">{log.description}</p>
                      )}
                      <div className="flex items-center justify-between text-xs text-gray-500">
                        <span>Visitor: {log.fingerprint_id ? log.fingerprint_id.substring(0, 8) + '...' : 'N/A'}</span>
                        <span>{new Date(log.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* High Risk Devices Tab */}
            {activeTab === 'devices' && (
              <div>
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">High Risk Devices</h3>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-500">Real-time:</span>
                    <button
                      onClick={() => setRealTimeEnabled(!realTimeEnabled)}
                      className={`px-3 py-1 rounded text-sm ${
                        realTimeEnabled 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {realTimeEnabled ? 'ON' : 'OFF'}
                    </button>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Visitor ID
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Risk Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          ML Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Bot Signals
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Activity
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {highRiskFingerprints.map((fingerprint) => {
                        const botSummary = getBotDetectionSummary(fingerprint)
                        return (
                          <tr key={fingerprint.id} className="hover:bg-gray-50">
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-mono text-gray-900">
                                {fingerprint.visitor_id.substring(0, 12)}...
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`px-2 py-1 text-xs rounded ${getRiskColor(fingerprint.risk_score)}`}>
                                {fingerprint.risk_score}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {fingerprint.ml_anomaly_score && (
                                <span className={`px-2 py-1 text-xs rounded ${
                                  fingerprint.ml_anomaly_score > 0.7 ? 'bg-red-100 text-red-800' :
                                  fingerprint.ml_anomaly_score > 0.4 ? 'bg-yellow-100 text-yellow-800' :
                                  'bg-green-100 text-green-800'
                                }`}>
                                  {(fingerprint.ml_anomaly_score * 100).toFixed(0)}%
                                </span>
                              )}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {botSummary.signals.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {botSummary.signals.slice(0, 2).map((signal, idx) => (
                                    <span key={idx} className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">
                                      {signal}
                                    </span>
                                  ))}
                                  {botSummary.signals.length > 2 && (
                                    <span className="px-2 py-1 text-xs bg-gray-100 text-gray-800 rounded">
                                      +{botSummary.signals.length - 2}
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <span className="text-xs text-gray-500">None</span>
                              )}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              <div>
                                <div>URLs: {fingerprint.activity_summary?.total_urls || 0}</div>
                                <div>Visits: {fingerprint.activity_summary?.total_visits || 0}</div>
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">
                              <button
                                onClick={() => analyzeFingerprint(fingerprint)}
                                className="text-blue-600 hover:text-blue-800 font-medium"
                              >
                                Analyze
                              </button>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Fraud Analysis Tab */}
            {activeTab === 'fraud' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Fraud Analysis</h3>
                {selectedFingerprint && fraudAnalysis ? (
                  <div className="space-y-6">
                    {/* Selected Fingerprint Info */}
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <h4 className="font-medium text-gray-900 mb-2">Selected Fingerprint</h4>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="font-medium">Visitor ID:</span>
                          <span className="ml-2 font-mono">{selectedFingerprint.visitor_id}</span>
                        </div>
                        <div>
                          <span className="font-medium">Risk Score:</span>
                          <span className={`ml-2 px-2 py-1 text-xs rounded ${getRiskColor(selectedFingerprint.risk_score)}`}>
                            {selectedFingerprint.risk_score}
                          </span>
                        </div>
                        <div>
                          <span className="font-medium">ML Anomaly Score:</span>
                          <span className="ml-2">
                            {fraudAnalysis.mlAnomaly.anomalyScore > 0.5 ? 'High' : 'Low'} 
                            ({(fraudAnalysis.mlAnomaly.anomalyScore * 100).toFixed(1)}%)
                          </span>
                        </div>
                        <div>
                          <span className="font-medium">Created:</span>
                          <span className="ml-2">{new Date(selectedFingerprint.created_at).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>

                    {/* Fraud Detection Results */}
                    <div className="bg-white border rounded-lg p-4">
                      <h4 className="font-medium text-gray-900 mb-3">Fraud Detection Results</h4>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Suspicious:</span>
                          <span className={`px-2 py-1 text-xs rounded ${
                            fraudAnalysis.fraudDetection.isSuspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                          }`}>
                            {fraudAnalysis.fraudDetection.isSuspicious ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Risk Score:</span>
                          <span className={`px-2 py-1 text-xs rounded ${getRiskColor(fraudAnalysis.fraudDetection.riskScore)}`}>
                            {fraudAnalysis.fraudDetection.riskScore}/10
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Confidence:</span>
                          <span className="text-sm">
                            {(fraudAnalysis.fraudDetection.confidence * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                      
                      {fraudAnalysis.fraudDetection.reasons.length > 0 && (
                        <div className="mt-4">
                          <h5 className="font-medium text-gray-700 mb-2">Risk Reasons:</h5>
                          <ul className="list-disc list-inside space-y-1 text-sm text-gray-600">
                            {fraudAnalysis.fraudDetection.reasons.map((reason: string, idx: number) => (
                              <li key={idx}>{reason}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {fraudAnalysis.fraudDetection.patterns.length > 0 && (
                        <div className="mt-4">
                          <h5 className="font-medium text-gray-700 mb-2">Detected Patterns:</h5>
                          <div className="flex flex-wrap gap-2">
                            {fraudAnalysis.fraudDetection.patterns.map((pattern: string, idx: number) => (
                              <span key={idx} className="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded">
                                {pattern.replace('_', ' ')}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* ML Anomaly Results */}
                    <div className="bg-white border rounded-lg p-4">
                      <h4 className="font-medium text-gray-900 mb-3">ML Anomaly Detection</h4>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Anomaly Detected:</span>
                          <span className={`px-2 py-1 text-xs rounded ${
                            fraudAnalysis.mlAnomaly.isAnomaly ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                          }`}>
                            {fraudAnalysis.mlAnomaly.isAnomaly ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Anomaly Score:</span>
                          <span className="text-sm">
                            {(fraudAnalysis.mlAnomaly.anomalyScore * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div>
                          <span className="font-medium">Explanation:</span>
                          <p className="text-sm text-gray-600 mt-1">{fraudAnalysis.mlAnomaly.explanation}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <p className="text-gray-500">Select a fingerprint from the "High Risk Devices" tab to analyze</p>
                  </div>
                )}
              </div>
            )}

            {/* Fraud Patterns Tab */}
            {activeTab === 'patterns' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Fraud Patterns Analysis</h3>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-medium text-gray-700 mb-3">Pattern Frequency (Last 7 Days)</h4>
                    <div className="space-y-3">
                      {Object.entries(stats.fraudPatterns).map(([pattern, data]: [string, any]) => (
                        <div key={pattern} className="bg-gray-50 p-3 rounded">
                          <div className="flex justify-between items-center mb-2">
                            <span className="font-medium capitalize">
                              {pattern.replace('_', ' ')}
                            </span>
                            <span className="text-sm text-gray-600">
                              {data.count} occurrences
                            </span>
                          </div>
                          <div className="flex justify-between items-center text-sm text-gray-600">
                            <span>Avg Severity: {data.avgSeverity.toFixed(1)}</span>
                            <span>Last: {new Date(data.lastOccurrence).toLocaleDateString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-700 mb-3">Risk Distribution</h4>
                    <div className="space-y-2">
                      {['critical', 'high', 'medium', 'low'].map((level) => {
                        const count = highRiskFingerprints.filter(fp => {
                          if (level === 'critical') return fp.risk_score >= 8
                          if (level === 'high') return fp.risk_score >= 6 && fp.risk_score < 8
                          if (level === 'medium') return fp.risk_score >= 3 && fp.risk_score < 6
                          return fp.risk_score < 3
                        }).length
                        
                        return (
                          <div key={level} className="flex items-center justify-between">
                            <span className="capitalize">{level}</span>
                            <div className="flex items-center space-x-2">
                              <div className="w-32 bg-gray-200 rounded-full h-2">
                                <div 
                                  className={`h-2 rounded-full ${
                                    level === 'critical' ? 'bg-red-500' :
                                    level === 'high' ? 'bg-orange-500' :
                                    level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                                  }`}
                                  style={{ width: `${(count / highRiskFingerprints.length) * 100}%` }}
                                ></div>
                              </div>
                              <span className="text-sm text-gray-600">{count}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ML Anomalies Tab */}
            {activeTab === 'ml' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">ML Anomaly Detection</h3>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-medium text-gray-700 mb-3">Anomaly Summary</h4>
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">Total Anomalies Detected:</span>
                        <span className="text-2xl font-bold text-blue-600">{stats.mlAnomalies}</span>
                      </div>
                      <div className="text-sm text-gray-600">
                        Out of {highRiskFingerprints.length} high-risk fingerprints analyzed
                      </div>
                    </div>
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-700 mb-3">Anomaly Thresholds</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>High Anomaly:</span>
                        <span className="text-red-600">≥ 70%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Medium Anomaly:</span>
                        <span className="text-yellow-600">40-69%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Low Anomaly:</span>
                        <span className="text-green-600">&lt; 40%</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-6">
                  <h4 className="font-medium text-gray-700 mb-3">Fingerprints with ML Anomalies</h4>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Visitor ID
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            ML Score
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Risk Score
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Explanation
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {highRiskFingerprints
                          .filter(fp => fp.ml_anomaly_score && fp.ml_anomaly_score > 0.3)
                          .sort((a, b) => (b.ml_anomaly_score || 0) - (a.ml_anomaly_score || 0))
                          .map((fingerprint) => (
                            <tr key={fingerprint.id}>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <div className="text-sm font-mono text-gray-900">
                                  {fingerprint.visitor_id.substring(0, 12)}...
                                </div>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <span className={`px-2 py-1 text-xs rounded ${
                                  (fingerprint.ml_anomaly_score || 0) > 0.7 ? 'bg-red-100 text-red-800' :
                                  (fingerprint.ml_anomaly_score || 0) > 0.4 ? 'bg-yellow-100 text-yellow-800' :
                                  'bg-green-100 text-green-800'
                                }`}>
                                  {((fingerprint.ml_anomaly_score || 0) * 100).toFixed(0)}%
                                </span>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <span className={`px-2 py-1 text-xs rounded ${getRiskColor(fingerprint.risk_score)}`}>
                                  {fingerprint.risk_score}
                                </span>
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-600">
                                ML anomaly detected in device characteristics
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Refresh Button */}
        <div className="mt-6 text-center space-x-4">
          <button
            onClick={loadDashboardData}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Refresh Data
          </button>
          
          <button
            onClick={async () => {
              console.log('🔍 Debug: Checking visit data...')
              const { data: visits, error } = await supabase
                .from('url_visits')
                .select('*')
                .order('visited_at', { ascending: false })
                .limit(5)
              
              if (error) {
                console.error('❌ Visit query error:', error)
                toast.error(`Visit query failed: ${error.message}`)
              } else {
                console.log('📊 Recent visits in database:', visits)
                toast.success(`Found ${visits?.length || 0} recent visits`)
              }
            }}
            className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 transition-colors"
          >
            Debug Visits
          </button>
        </div>
      </div>
    </div>
  )
}

export default AdminDashboard
