// Advanced Fraud Detection System with ML-based Anomaly Detection
import { supabase } from './supabase'
import { logRiskEvent } from './fingerprint'

export interface FraudDetectionResult {
  isSuspicious: boolean
  riskScore: number
  reasons: string[]
  severity: number
  confidence: number
  patterns: string[]
  mlScore?: number
}

export interface AnomalyDetectionResult {
  isAnomaly: boolean
  anomalyScore: number
  features: Record<string, number>
  explanation: string
}

// Advanced risk scoring with multiple detection patterns
export class AdvancedFraudDetector {
  private static instance: AdvancedFraudDetector
  
  public static getInstance(): AdvancedFraudDetector {
    if (!AdvancedFraudDetector.instance) {
      AdvancedFraudDetector.instance = new AdvancedFraudDetector()
    }
    return AdvancedFraudDetector.instance
  }

  // Multi-account reuse detection
  async detectMultiAccountReuse(fingerprintId: string): Promise<FraudDetectionResult> {
    const reasons: string[] = []
    let riskScore = 0
    let severity = 1
    const patterns: string[] = []

    try {
      // Get fingerprint data
      const { data: fingerprint } = await supabase
        .from('fingerprints')
        .select('visitor_id, device_info')
        .eq('id', fingerprintId)
        .single()

      if (!fingerprint) return this.createEmptyResult()

      // Check for duplicate visitor IDs
      const { data: duplicates } = await supabase
        .from('fingerprints')
        .select('id, created_at')
        .eq('visitor_id', fingerprint.visitor_id)
        .neq('id', fingerprintId)

      if (duplicates && duplicates.length > 0) {
        reasons.push(`Duplicate fingerprint detected: ${duplicates.length + 1} instances`)
        riskScore += 4
        severity = Math.max(severity, 4)
        patterns.push('duplicate_fingerprint')
      }

      // Check for similar device signatures across different accounts
      const deviceInfo = fingerprint.device_info
      if (deviceInfo) {
        const { data: similarDevices } = await supabase
          .from('fingerprints')
          .select('id, visitor_id, created_at')
          .neq('id', fingerprintId)
          .or(`device_info->canvas.eq.${deviceInfo.canvas},device_info->webgl.eq.${deviceInfo.webgl},device_info->audio.eq.${deviceInfo.audio}`)

        if (similarDevices && similarDevices.length > 2) {
          reasons.push(`Similar device signatures across ${similarDevices.length} fingerprints`)
          riskScore += 3
          severity = Math.max(severity, 3)
          patterns.push('similar_device_signature')
        }
      }

    } catch (error) {
      console.error('Error detecting multi-account reuse:', error)
    }

    return {
      isSuspicious: riskScore > 2,
      riskScore,
      reasons,
      severity,
      confidence: Math.min(riskScore / 10, 1),
      patterns
    }
  }

  // High velocity URL creation detection
  async detectHighVelocity(fingerprintId: string): Promise<FraudDetectionResult> {
    const reasons: string[] = []
    let riskScore = 0
    let severity = 1
    const patterns: string[] = []

    try {
      // Check URLs created in last hour
      const { data: recentUrls } = await supabase
        .from('urls')
        .select('created_at')
        .eq('fingerprint_id', fingerprintId)
        .gte('created_at', new Date(Date.now() - 60 * 60 * 1000).toISOString())

      if (recentUrls) {
        const urlCount = recentUrls.length
        
        if (urlCount > 20) {
          reasons.push(`Extreme URL creation velocity: ${urlCount} URLs/hour`)
          riskScore += 4
          severity = Math.max(severity, 4)
          patterns.push('extreme_velocity')
        } else if (urlCount > 10) {
          reasons.push(`High URL creation velocity: ${urlCount} URLs/hour`)
          riskScore += 3
          severity = Math.max(severity, 3)
          patterns.push('high_velocity')
        } else if (urlCount > 5) {
          reasons.push(`Moderate URL creation velocity: ${urlCount} URLs/hour`)
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('moderate_velocity')
        }

        // Check for burst patterns (multiple URLs in short time)
        const timeGaps = recentUrls
          .map((url: any, index: number) => {
            if (index === 0) return 0
            return new Date(url.created_at).getTime() - new Date(recentUrls[index - 1].created_at).getTime()
          })
          .filter((gap: number) => gap < 60000) // Less than 1 minute

        if (timeGaps.length > 3) {
          reasons.push(`Burst pattern detected: ${timeGaps.length} URLs created within 1-minute intervals`)
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('burst_pattern')
        }
      }

    } catch (error) {
      console.error('Error detecting high velocity:', error)
    }

    return {
      isSuspicious: riskScore > 1,
      riskScore,
      reasons,
      severity,
      confidence: Math.min(riskScore / 10, 1),
      patterns
    }
  }

  // Click fraud detection
  async detectClickFraud(fingerprintId: string): Promise<FraudDetectionResult> {
    const reasons: string[] = []
    let riskScore = 0
    let severity = 1
    const patterns: string[] = []

    try {
      // Get visit patterns
      const { data: visits } = await supabase
        .from('url_visits')
        .select('visited_at, url_id, referrer')
        .eq('fingerprint_id', fingerprintId)
        .gte('visited_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())

      if (visits && visits.length > 0) {
        const visitCount = visits.length
        
        // High visit volume
        if (visitCount > 100) {
          reasons.push(`High visit volume: ${visitCount} visits in 24h`)
          riskScore += 3
          severity = Math.max(severity, 3)
          patterns.push('high_visit_volume')
        }

        // Check for rapid clicking patterns
        const rapidClicks = visits.filter((visit: any, index: number) => {
          if (index === 0) return false
          const timeDiff = new Date(visit.visited_at).getTime() - new Date(visits[index - 1].visited_at).getTime()
          return timeDiff < 5000 // Less than 5 seconds
        })

        if (rapidClicks.length > 5) {
          reasons.push(`Rapid clicking pattern: ${rapidClicks.length} clicks within 5-second intervals`)
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('rapid_clicking')
        }

        // Check for missing referrers (direct access)
        const directAccess = visits.filter((visit: any) => !visit.referrer || visit.referrer === '')
        if (directAccess.length > visitCount * 0.8) {
          reasons.push(`High direct access rate: ${Math.round((directAccess.length / visitCount) * 100)}%`)
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('direct_access')
        }
      }

    } catch (error) {
      console.error('Error detecting click fraud:', error)
    }

    return {
      isSuspicious: riskScore > 1,
      riskScore,
      reasons,
      severity,
      confidence: Math.min(riskScore / 10, 1),
      patterns
    }
  }

  // Bot and automation detection
  async detectBotSignals(fingerprintId: string): Promise<FraudDetectionResult> {
    const reasons: string[] = []
    let riskScore = 0
    let severity = 1
    const patterns: string[] = []

    try {
      const { data: fingerprint } = await supabase
        .from('fingerprints')
        .select('device_info, browser_info')
        .eq('id', fingerprintId)
        .single()

      if (!fingerprint) return this.createEmptyResult()

      const deviceInfo = fingerprint.device_info
      const browserInfo = fingerprint.browser_info

      // Check for automation signals
      if (deviceInfo) {
        if (deviceInfo.webdriver === true) {
          reasons.push('WebDriver automation detected')
          riskScore += 4
          severity = Math.max(severity, 4)
          patterns.push('webdriver')
        }

        if (deviceInfo.phantom === true) {
          reasons.push('PhantomJS detected')
          riskScore += 4
          severity = Math.max(severity, 4)
          patterns.push('phantomjs')
        }

        if (deviceInfo.selenium === true) {
          reasons.push('Selenium automation detected')
          riskScore += 4
          severity = Math.max(severity, 4)
          patterns.push('selenium')
        }

        if (deviceInfo.headless === true) {
          reasons.push('Headless browser detected')
          riskScore += 3
          severity = Math.max(severity, 3)
          patterns.push('headless')
        }

        if (deviceInfo.automation === true) {
          reasons.push('Browser automation detected')
          riskScore += 3
          severity = Math.max(severity, 3)
          patterns.push('automation')
        }

        // Check for missing hardware features (common in bots)
        if (deviceInfo.hardwareConcurrency === 0 || deviceInfo.hardwareConcurrency === null) {
          reasons.push('Missing hardware concurrency information')
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('missing_hardware')
        }

        if (deviceInfo.deviceMemory === 0 || deviceInfo.deviceMemory === null) {
          reasons.push('Missing device memory information')
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('missing_memory')
        }

        // Check for unusual plugin configurations
        if (!deviceInfo.plugins || deviceInfo.plugins.length === 0) {
          reasons.push('No browser plugins detected')
          riskScore += 1
          severity = Math.max(severity, 1)
          patterns.push('no_plugins')
        }
      }

    } catch (error) {
      console.error('Error detecting bot signals:', error)
    }

    return {
      isSuspicious: riskScore > 0,
      riskScore,
      reasons,
      severity,
      confidence: Math.min(riskScore / 10, 1),
      patterns
    }
  }

  // Device/browser anomaly detection
  async detectDeviceAnomalies(fingerprintId: string): Promise<FraudDetectionResult> {
    const reasons: string[] = []
    let riskScore = 0
    let severity = 1
    const patterns: string[] = []

    try {
      const { data: fingerprint } = await supabase
        .from('fingerprints')
        .select('device_info, browser_info')
        .eq('id', fingerprintId)
        .single()

      if (!fingerprint) return this.createEmptyResult()

      const deviceInfo = fingerprint.device_info
      const browserInfo = fingerprint.browser_info

      if (deviceInfo && browserInfo) {
        // Check for unusual browser/device combinations
        const userAgent = deviceInfo.userAgent || browserInfo.userAgent || ''
        const platform = deviceInfo.platform || browserInfo.platform || ''
        const touchSupport = deviceInfo.touchSupport
        const screenResolution = deviceInfo.screenResolution

        // Mobile browser on desktop platform
        if (deviceInfo.mobile === true && platform.toLowerCase().includes('win')) {
          reasons.push('Mobile browser on Windows platform')
          riskScore += 2
          severity = Math.max(severity, 2)
          patterns.push('mobile_desktop_mismatch')
        }

        // Touch support mismatch
        if (touchSupport === true && !userAgent.toLowerCase().includes('mobile') && !userAgent.toLowerCase().includes('android')) {
          reasons.push('Touch support without mobile indicators')
          riskScore += 1
          severity = Math.max(severity, 1)
          patterns.push('touch_mismatch')
        }

        // Unusual screen resolution
        if (screenResolution) {
          const [width, height] = screenResolution.split('x').map(Number)
          if (width < 800 || height < 600) {
            reasons.push(`Unusual screen resolution: ${screenResolution}`)
            riskScore += 1
            severity = Math.max(severity, 1)
            patterns.push('unusual_resolution')
          }
        }

        // Check for missing common browser features
        if (browserInfo.capabilities) {
          const caps = browserInfo.capabilities
          if (!caps.webgl && !caps.webgl2) {
            reasons.push('WebGL not supported')
            riskScore += 1
            severity = Math.max(severity, 1)
            patterns.push('no_webgl')
          }

          if (!caps.localStorage || !caps.sessionStorage) {
            reasons.push('Storage APIs not supported')
            riskScore += 1
            severity = Math.max(severity, 1)
            patterns.push('no_storage')
          }
        }
      }

    } catch (error) {
      console.error('Error detecting device anomalies:', error)
    }

    return {
      isSuspicious: riskScore > 0,
      riskScore,
      reasons,
      severity,
      confidence: Math.min(riskScore / 10, 1),
      patterns
    }
  }

  // ML-based anomaly detection using numeric features
  async detectMLAnomalies(fingerprintId: string): Promise<AnomalyDetectionResult> {
    try {
      const { data: fingerprint } = await supabase
        .from('fingerprints')
        .select('device_info, browser_info, created_at')
        .eq('id', fingerprintId)
        .single()

      if (!fingerprint) {
        return {
          isAnomaly: false,
          anomalyScore: 0,
          features: {},
          explanation: 'No fingerprint data available'
        }
      }

      // Extract numeric features for ML analysis
      const features: Record<string, number> = {}
      const deviceInfo = fingerprint.device_info
      const browserInfo = fingerprint.browser_info

      if (deviceInfo) {
        features.hardwareConcurrency = deviceInfo.hardwareConcurrency || 0
        features.deviceMemory = deviceInfo.deviceMemory || 0
        features.touchSupport = deviceInfo.touchSupport ? 1 : 0
        features.mobile = deviceInfo.mobile ? 1 : 0
        
        // Screen resolution features
        if (deviceInfo.screenResolution) {
          const [width, height] = deviceInfo.screenResolution.split('x').map(Number)
          features.screenWidth = width || 0
          features.screenHeight = height || 0
          features.screenArea = (width || 0) * (height || 0)
        }

        // Bot detection features
        features.webdriver = deviceInfo.webdriver ? 1 : 0
        features.phantom = deviceInfo.phantom ? 1 : 0
        features.selenium = deviceInfo.selenium ? 1 : 0
        features.headless = deviceInfo.headless ? 1 : 0
        features.automation = deviceInfo.automation ? 1 : 0
      }

      if (browserInfo && browserInfo.capabilities) {
        const caps = browserInfo.capabilities
        features.webgl = caps.webgl ? 1 : 0
        features.webgl2 = caps.webgl2 ? 1 : 0
        features.webAudio = caps.webAudio ? 1 : 0
        features.webRTC = caps.webRTC ? 1 : 0
        features.geolocation = caps.geolocation ? 1 : 0
        features.notifications = caps.notifications ? 1 : 0
        features.serviceWorker = caps.serviceWorker ? 1 : 0
        features.indexedDB = caps.indexedDB ? 1 : 0
        features.localStorage = caps.localStorage ? 1 : 0
        features.sessionStorage = caps.sessionStorage ? 1 : 0
        features.touchEvents = caps.touchEvents ? 1 : 0
        features.devicePixelRatio = caps.devicePixelRatio || 1
      }

      // Simple anomaly detection based on feature combinations
      let anomalyScore = 0
      const explanations: string[] = []

      // Check for unusual hardware configurations
      if (features.hardwareConcurrency === 0 && features.deviceMemory === 0) {
        anomalyScore += 0.3
        explanations.push('Missing hardware information')
      }

      // Check for bot-like behavior
      const botSignals = features.webdriver + features.phantom + features.selenium + features.headless + features.automation
      if (botSignals > 0) {
        anomalyScore += botSignals * 0.2
        explanations.push(`${botSignals} bot detection signals`)
      }

      // Check for unusual screen configurations
      if (features.screenArea > 0 && features.screenArea < 480000) { // Less than 800x600
        anomalyScore += 0.2
        explanations.push('Unusually small screen area')
      }

      // Check for missing common browser features
      const missingFeatures = (features.webgl ? 0 : 1) + (features.localStorage ? 0 : 1) + (features.sessionStorage ? 0 : 1)
      if (missingFeatures > 1) {
        anomalyScore += missingFeatures * 0.1
        explanations.push(`${missingFeatures} missing common browser features`)
      }

      return {
        isAnomaly: anomalyScore > 0.5,
        anomalyScore: Math.min(anomalyScore, 1),
        features,
        explanation: explanations.join(', ') || 'No anomalies detected'
      }

    } catch (error) {
      console.error('Error in ML anomaly detection:', error)
      return {
        isAnomaly: false,
        anomalyScore: 0,
        features: {},
        explanation: 'Error in anomaly detection'
      }
    }
  }

  // Comprehensive fraud detection
  async performComprehensiveDetection(fingerprintId: string, url?: string): Promise<FraudDetectionResult> {
    try {
      // Run all detection methods
      const [
        multiAccountResult,
        velocityResult,
        clickFraudResult,
        botResult,
        deviceAnomalyResult,
        mlAnomalyResult
      ] = await Promise.all([
        this.detectMultiAccountReuse(fingerprintId),
        this.detectHighVelocity(fingerprintId),
        this.detectClickFraud(fingerprintId),
        this.detectBotSignals(fingerprintId),
        this.detectDeviceAnomalies(fingerprintId),
        this.detectMLAnomalies(fingerprintId)
      ])

      // Combine results
      const allReasons = [
        ...multiAccountResult.reasons,
        ...velocityResult.reasons,
        ...clickFraudResult.reasons,
        ...botResult.reasons,
        ...deviceAnomalyResult.reasons
      ]

      const allPatterns = [
        ...multiAccountResult.patterns,
        ...velocityResult.patterns,
        ...clickFraudResult.patterns,
        ...botResult.patterns,
        ...deviceAnomalyResult.patterns
      ]

      const totalRiskScore = Math.min(
        multiAccountResult.riskScore +
        velocityResult.riskScore +
        clickFraudResult.riskScore +
        botResult.riskScore +
        deviceAnomalyResult.riskScore +
        (mlAnomalyResult.anomalyScore * 5), // Convert ML score to risk score
        10
      )

      const maxSeverity = Math.max(
        multiAccountResult.severity,
        velocityResult.severity,
        clickFraudResult.severity,
        botResult.severity,
        deviceAnomalyResult.severity
      )

      const result: FraudDetectionResult = {
        isSuspicious: totalRiskScore > 3,
        riskScore: totalRiskScore,
        reasons: Array.from(new Set(allReasons)), // Remove duplicates
        severity: maxSeverity,
        confidence: Math.min(totalRiskScore / 10, 1),
        patterns: Array.from(new Set(allPatterns)), // Remove duplicates
        mlScore: mlAnomalyResult.anomalyScore
      }

      // Log risk event if suspicious
      if (result.isSuspicious) {
        await logRiskEvent(
          fingerprintId,
          'comprehensive_fraud_detection',
          `Advanced fraud detected: ${result.reasons.join('; ')}`,
          result.severity,
          {
            detectionResults: {
              multiAccount: multiAccountResult,
              velocity: velocityResult,
              clickFraud: clickFraudResult,
              bot: botResult,
              deviceAnomaly: deviceAnomalyResult,
              mlAnomaly: mlAnomalyResult
            },
            url: url,
            timestamp: new Date().toISOString()
          }
        )
      }

      return result

    } catch (error) {
      console.error('Error in comprehensive fraud detection:', error)
      return this.createEmptyResult()
    }
  }

  private createEmptyResult(): FraudDetectionResult {
    return {
      isSuspicious: false,
      riskScore: 0,
      reasons: [],
      severity: 1,
      confidence: 0,
      patterns: []
    }
  }
}

// Export singleton instance
export const fraudDetector = AdvancedFraudDetector.getInstance()

// Convenience functions
export const detectFraud = (fingerprintId: string, url?: string) => 
  fraudDetector.performComprehensiveDetection(fingerprintId, url)

export const detectMLAnomalies = (fingerprintId: string) => 
  fraudDetector.detectMLAnomalies(fingerprintId)
