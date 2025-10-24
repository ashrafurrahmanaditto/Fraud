// Fraud detection utilities
import { supabase } from './supabase'
import { logRiskEvent } from './fingerprint'

export interface FraudDetectionResult {
  isSuspicious: boolean
  riskScore: number
  reasons: string[]
  severity: number
}

// Detect suspicious URL patterns
export const detectSuspiciousUrls = (url: string): FraudDetectionResult => {
  const reasons: string[] = []
  let riskScore = 0
  let severity = 1

  // Check for known spam/shortener domains
  const spamDomains = [
    'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
    'ow.ly', 'buff.ly', 'is.gd', 'v.gd', 'shorturl.at'
  ]

  const urlObj = new URL(url)
  const domain = urlObj.hostname.toLowerCase()

  if (spamDomains.some(spamDomain => domain.includes(spamDomain))) {
    reasons.push('Suspicious domain detected')
    riskScore += 2
    severity = Math.max(severity, 2)
  }

  // Check for suspicious patterns in URL
  const suspiciousPatterns = [
    /[0-9]{10,}/, // Long number sequences
    /[a-z]{20,}/, // Very long character sequences
    /[^a-zA-Z0-9\-\.\/\?\=\&\%\#\:\+]/ // Unusual characters
  ]

  suspiciousPatterns.forEach(pattern => {
    if (pattern.test(url)) {
      reasons.push('Suspicious URL pattern detected')
      riskScore += 1
    }
  })

  // Check URL length
  if (url.length > 200) {
    reasons.push('Unusually long URL')
    riskScore += 1
  }

  return {
    isSuspicious: riskScore > 0,
    riskScore,
    reasons,
    severity
  }
}

// Detect suspicious fingerprint behavior
export const detectSuspiciousFingerprint = async (fingerprintId: string): Promise<FraudDetectionResult> => {
  const reasons: string[] = []
  let riskScore = 0
  let severity = 1

  try {
    // Check for multiple URLs from same fingerprint
    const { data: urlCount } = await supabase
      .from('urls')
      .select('id', { count: 'exact' })
      .eq('fingerprint_id', fingerprintId)

    if (urlCount && urlCount.length > 10) {
      reasons.push(`High volume URL creation: ${urlCount.length} URLs`)
      riskScore += 3
      severity = Math.max(severity, 3)
    } else if (urlCount && urlCount.length > 5) {
      reasons.push(`Moderate URL creation: ${urlCount.length} URLs`)
      riskScore += 1
    }

    // Check for rapid URL creation
    const { data: recentUrls } = await supabase
      .from('urls')
      .select('created_at')
      .eq('fingerprint_id', fingerprintId)
      .gte('created_at', new Date(Date.now() - 60 * 60 * 1000).toISOString()) // Last hour

    if (recentUrls && recentUrls.length > 5) {
      reasons.push(`Rapid URL creation: ${recentUrls.length} in last hour`)
      riskScore += 2
      severity = Math.max(severity, 2)
    }

    // Check for duplicate fingerprints (same visitor_id)
    const { data: fingerprint } = await supabase
      .from('fingerprints')
      .select('visitor_id')
      .eq('id', fingerprintId)
      .single()

    if (fingerprint) {
      const { data: duplicateCount } = await supabase
        .from('fingerprints')
        .select('id', { count: 'exact' })
        .eq('visitor_id', fingerprint.visitor_id)

      if (duplicateCount && duplicateCount.length > 1) {
        reasons.push(`Duplicate fingerprint detected: ${duplicateCount.length} instances`)
        riskScore += 4
        severity = Math.max(severity, 4)
      }
    }

    // Check for suspicious visit patterns
    const { data: visitCount } = await supabase
      .from('url_visits')
      .select('id', { count: 'exact' })
      .eq('fingerprint_id', fingerprintId)
      .gte('visited_at', new Date(Date.now() - 60 * 60 * 1000).toISOString())

    if (visitCount && visitCount.length > 50) {
      reasons.push(`High visit volume: ${visitCount.length} visits in last hour`)
      riskScore += 2
      severity = Math.max(severity, 2)
    }

    // Check existing risk logs
    const { data: riskLogs } = await supabase
      .from('risk_logs')
      .select('severity')
      .eq('fingerprint_id', fingerprintId)
      .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())

    if (riskLogs && riskLogs.length > 0) {
      const maxSeverity = Math.max(...riskLogs.map((log: any) => log.severity))
      reasons.push(`Previous risk events: ${riskLogs.length} in last 24h`)
      riskScore += riskLogs.length
      severity = Math.max(severity, maxSeverity)
    }

  } catch (error) {
    console.error('Error detecting suspicious fingerprint:', error)
  }

  return {
    isSuspicious: riskScore > 2,
    riskScore,
    reasons,
    severity
  }
}

// Comprehensive fraud detection
export const performFraudDetection = async (
  fingerprintId: string,
  url: string
): Promise<FraudDetectionResult> => {
  const urlDetection = detectSuspiciousUrls(url)
  const fingerprintDetection = await detectSuspiciousFingerprint(fingerprintId)

  const combinedReasons = [...urlDetection.reasons, ...fingerprintDetection.reasons]
  const combinedRiskScore = urlDetection.riskScore + fingerprintDetection.riskScore
  const combinedSeverity = Math.max(urlDetection.severity, fingerprintDetection.severity)

  const result: FraudDetectionResult = {
    isSuspicious: combinedRiskScore > 2,
    riskScore: combinedRiskScore,
    reasons: combinedReasons,
    severity: combinedSeverity
  }

  // Log risk event if suspicious
  if (result.isSuspicious) {
    await logRiskEvent(
      fingerprintId,
      'comprehensive_fraud_detection',
      `Fraud detected: ${result.reasons.join(', ')}`,
      result.severity,
      {
        urlDetection,
        fingerprintDetection,
        combinedResult: result
      }
    )
  }

  return result
}

// Email notification system (placeholder)
export const sendEmailAlert = async (
  subject: string,
  message: string,
  severity: number
): Promise<boolean> => {
  // This would integrate with your email service (SendGrid, AWS SES, etc.)
  console.log(`Email Alert [Severity ${severity}]: ${subject} - ${message}`)
  
  // For now, just log to console
  // In production, implement actual email sending
  return true
}

// Rate limiting utilities
export const checkAdvancedRateLimit = async (
  fingerprintId: string,
  actionType: string,
  customLimits?: { maxAttempts: number; windowMinutes: number }
): Promise<boolean> => {
  const limits = customLimits || {
    maxAttempts: actionType === 'url_creation' ? 10 : 100,
    windowMinutes: actionType === 'url_creation' ? 60 : 5
  }

  try {
    const { data, error } = await supabase.rpc('check_rate_limit', {
      fingerprint_uuid: fingerprintId,
      action_type_param: actionType,
      max_attempts: limits.maxAttempts,
      window_minutes: limits.windowMinutes
    })

    if (error) {
      console.error('Error checking advanced rate limit:', error)
      return false
    }

    return data
  } catch (error) {
    console.error('Error checking advanced rate limit:', error)
    return false
  }
}

// Device reputation scoring
export const calculateDeviceReputation = async (fingerprintId: string): Promise<number> => {
  try {
    const { data, error } = await supabase.rpc('calculate_risk_score', {
      fingerprint_uuid: fingerprintId
    })

    if (error) {
      console.error('Error calculating device reputation:', error)
      return 0
    }

    return data || 0
  } catch (error) {
    console.error('Error calculating device reputation:', error)
    return 0
  }
}
