import React, { useState, useEffect } from 'react'
import { supabase, Url, Fingerprint } from '../lib/supabase'
import { getOrCreateFingerprint, checkRateLimit, logRiskEvent, logUrlVisit, getUrlVisitCount } from '../lib/fingerprint'
import { performFraudDetection } from '../lib/fraudDetection'
import { AdvancedFraudDetector } from '../lib/advancedFraudDetection'
import { mlFraudDetector } from '../lib/mlFraudDetection'
import toast from 'react-hot-toast'

const UrlShortener: React.FC = () => {
  const [url, setUrl] = useState('')
  const [shortenedUrl, setShortenedUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [fingerprint, setFingerprint] = useState<Fingerprint | null>(null)
  const [visitCount, setVisitCount] = useState<number | null>(null)
  const [testingVisits, setTestingVisits] = useState(false)

  useEffect(() => {
    // Initialize fingerprint on component mount
    const initFingerprint = async () => {
      try {
        const fp = await getOrCreateFingerprint()
        setFingerprint(fp)
      } catch (error) {
        console.error('Failed to initialize fingerprint:', error)
        console.log('This is expected if Supabase is not configured yet')
        // Don't show error toast for missing Supabase config
        // toast.error('Failed to initialize device tracking')
      }
    }

    initFingerprint()
  }, [])

  const generateShortCode = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    let result = ''
    for (let i = 0; i < 6; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return result
  }

  const shortenUrl = async (e: React.FormEvent) => {
    e.preventDefault()
    
    console.log('🚀 Starting URL shortening process...')
    
    if (!url.trim()) {
      toast.error('Please enter a valid URL')
      return
    }

    // Validate URL
    try {
      new URL(url)
    } catch {
      toast.error('Please enter a valid URL')
      return
    }

    console.log('📝 URL validation passed:', url)
    setLoading(true)

    try {
      // If no fingerprint (Supabase not configured), just generate a local short code
      if (!fingerprint) {
        console.log('⚠️ No fingerprint available - using local mode')
        const shortCode = generateShortCode()
        const shortUrl = `${window.location.origin}/${shortCode}`
        setShortenedUrl(shortUrl)
        toast.success('URL shortened locally! (Not saved to database)')
        setUrl('')
        setLoading(false)
        return
      }

      console.log('📱 Fingerprint available:', fingerprint.id)

      // Check rate limit
      console.log('⏱️ Checking rate limit...')
      const rateLimitOk = await checkRateLimit(fingerprint.id, 'url_creation')
      console.log('⏱️ Rate limit check result:', rateLimitOk)
      
      if (!rateLimitOk) {
        toast.error('Rate limit exceeded. Please try again later.')
        setLoading(false)
        return
      }

      // Generate short code
      console.log('🔗 Generating short code...')
      let shortCode = generateShortCode()
      console.log('🔗 Initial short code:', shortCode)
      
      // Ensure uniqueness
      let attempts = 0
      while (attempts < 10) {
        const { data: existing } = await supabase
          .from('urls')
          .select('id')
          .eq('short_code', shortCode)
          .single()

        if (!existing) break
        
        shortCode = generateShortCode()
        attempts++
      }

      if (attempts >= 10) {
        toast.error('Failed to generate unique short code. Please try again.')
        setLoading(false)
        return
      }

      console.log('🔗 Final short code:', shortCode)

      // Create URL record
      console.log('💾 Saving URL to database...')
      const { data, error } = await supabase
        .from('urls')
        .insert({
          original_url: url,
          short_code: shortCode,
          fingerprint_id: fingerprint.id
        })
        .select()
        .single()

      if (error) {
        console.error('❌ Database error:', error)
        toast.error('Failed to shorten URL. Please try again.')
        setLoading(false)
        return
      }

      console.log('✅ URL saved successfully:', data)

      const shortUrl = `${window.location.origin}/${shortCode}`
      setShortenedUrl(shortUrl)

      // Log this URL creation as a visit (for counting purposes)
      console.log('📊 Logging URL creation as visit...')
      try {
        await logUrlVisit(data.id, fingerprint.id)
        console.log('📊 Visit logged successfully')
      } catch (visitError) {
        console.error('❌ Error logging URL creation visit:', visitError)
        // Don't fail the entire operation if visit logging fails
        toast.error('Visit logging failed, but URL was created successfully')
      }

      // Check for suspicious patterns and log risk events
      console.log('🔍 Running fraud detection...')
      await checkForSuspiciousActivity(fingerprint.id, url)
      console.log('🔍 Fraud detection completed')

      toast.success('URL shortened successfully!')
      setUrl('')
      
      // Refresh visit count for the new URL
      setTimeout(() => {
        refreshVisitCount()
      }, 1000)

    } catch (error) {
      console.error('Error shortening URL:', error)
      toast.error('An error occurred. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const checkForSuspiciousActivity = async (fingerprintId: string, originalUrl: string) => {
    try {
      console.log('🔍 Running comprehensive fraud detection...')
      
      // Get fingerprint data for ML detection
      const { data: fingerprintData } = await supabase
        .from('fingerprints')
        .select('device_info, browser_info')
        .eq('id', fingerprintId)
        .single()
      
      // Run ML-based fraud detection
      let mlResult = null
      if (fingerprintData) {
        mlResult = await mlFraudDetector.detectFraud(fingerprintData.device_info)
        console.log('🤖 ML Fraud Detection:', mlResult)
      }
      
      // Run comprehensive fraud detection
      const fraudResult = await performFraudDetection(fingerprintId, originalUrl)
      
      // Run advanced fraud detection
      const fraudDetector = AdvancedFraudDetector.getInstance()
      const botDetection = await fraudDetector.detectBotSignals(fingerprintId)
      const multiAccountDetection = await fraudDetector.detectMultiAccountReuse(fingerprintId)
      const clickFraudDetection = await fraudDetector.detectClickFraud(fingerprintId)
      
      // Combine all detection results
      const allReasons = [
        ...fraudResult.reasons,
        ...botDetection.reasons,
        ...multiAccountDetection.reasons,
        ...clickFraudDetection.reasons,
        ...(mlResult?.anomalies || []),
        ...(mlResult?.botSignals || [])
      ]
      
      const maxRiskScore = Math.max(
        fraudResult.riskScore,
        botDetection.riskScore,
        multiAccountDetection.riskScore,
        clickFraudDetection.riskScore,
        mlResult?.riskScore || 0
      )
      
      const maxSeverity = Math.max(
        fraudResult.severity,
        botDetection.severity,
        multiAccountDetection.severity,
        clickFraudDetection.severity,
        mlResult?.isFraudulent ? 4 : 1
      )
      
      // Debug logging for all visits
      console.log('🔍 Visit Debug Info:', {
        fingerprintId,
        url: originalUrl,
        allReasons,
        maxRiskScore,
        maxSeverity,
        mlResult,
        fraudResult,
        botDetection,
        multiAccountDetection,
        clickFraudDetection
      })

      // Log comprehensive fraud detection results
      if (allReasons.length > 0 || mlResult?.isFraudulent) {
        console.log('🚨 Fraud detected:', {
          reasons: allReasons,
          riskScore: maxRiskScore,
          severity: maxSeverity,
          fingerprintId,
          url: originalUrl,
          mlResult,
          detectionSummary: mlResult ? mlFraudDetector.getDetectionSummary(mlResult) : null
        })
        
        await logRiskEvent(
          fingerprintId,
          'comprehensive_fraud_detection',
          `Advanced fraud detection triggered: ${allReasons.join(', ')}${mlResult ? ` | ML: ${mlFraudDetector.getDetectionSummary(mlResult)}` : ''}`,
          maxSeverity,
          {
            fraudResult,
            botDetection,
            multiAccountDetection,
            clickFraudDetection,
            mlResult,
            originalUrl,
            timestamp: new Date().toISOString()
          }
        )
        
        // Show warning to user if high risk
        if (maxRiskScore >= 5 || mlResult?.isFraudulent) {
          const message = mlResult?.isFraudulent 
            ? `🚨 ML Fraud Detection: ${mlFraudDetector.getDetectionSummary(mlResult)}`
            : `High-risk activity detected: ${allReasons[0]}`
          toast.error(message)
        } else if (maxRiskScore >= 3) {
          toast.error(`Suspicious activity detected: ${allReasons[0]}`)
        }
      } else {
        console.log('✅ No fraud detected')
      }

    } catch (error) {
      console.error('Error checking suspicious activity:', error)
    }
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(shortenedUrl)
      toast.success('URL copied to clipboard!')
    } catch (error) {
      toast.error('Failed to copy URL')
    }
  }

  const testVisitCounting = async () => {
    if (!shortenedUrl) {
      toast.error('Please create a shortened URL first')
      return
    }

    setTestingVisits(true)
    try {
      // Extract URL ID from the shortened URL (this is a simplified approach)
      const urlParts = shortenedUrl.split('/')
      const shortCode = urlParts[urlParts.length - 1]
      
      // Get the URL record to find the ID
      const { data: urlData } = await supabase
        .from('urls')
        .select('id')
        .eq('short_code', shortCode)
        .single()

      if (!urlData) {
        toast.error('Could not find URL record')
        return
      }

      // Test visit logging
      if (fingerprint) {
        await logUrlVisit(urlData.id, fingerprint.id)
        toast.success('Test visit logged successfully!')
      } else {
        await logUrlVisit(urlData.id)
        toast.success('Test visit logged successfully (no fingerprint)!')
      }

      // Get updated visit count
      const count = await getUrlVisitCount(urlData.id)
      setVisitCount(count)
      
      toast.success(`Visit count updated: ${count}`)
      
    } catch (error) {
      console.error('Error testing visit counting:', error)
      toast.error('Failed to test visit counting')
    } finally {
      setTestingVisits(false)
    }
  }

  const refreshVisitCount = async () => {
    if (!shortenedUrl) return

    try {
      const urlParts = shortenedUrl.split('/')
      const shortCode = urlParts[urlParts.length - 1]
      
      const { data: urlData } = await supabase
        .from('urls')
        .select('id')
        .eq('short_code', shortCode)
        .single()

      if (urlData) {
        const count = await getUrlVisitCount(urlData.id)
        setVisitCount(count)
      }
    } catch (error) {
      console.error('Error refreshing visit count:', error)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-gray-900 mb-4">
              URL Shortener
            </h1>
            <p className="text-lg text-gray-600">
              Shorten your URLs with advanced fraud detection
            </p>
          </div>

          {/* URL Shortener Form */}
          <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
            <form onSubmit={shortenUrl} className="space-y-4">
              <div>
                <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
                  Enter URL to shorten
                </label>
                <input
                  type="url"
                  id="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  required
                />
              </div>
              
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? 'Shortening...' : 'Shorten URL'}
              </button>
              
              {!fingerprint && (
                <div className="mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <p className="text-sm text-yellow-800">
                    <strong>Note:</strong> Supabase is not configured yet. The URL will be shortened locally but won't be saved to the database. 
                    <br />
                    <a href="#setup" className="underline">Click here to set up Supabase</a>
                  </p>
                </div>
              )}
            </form>

            {/* Result */}
            {shortenedUrl && (
              <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                <h3 className="text-sm font-medium text-green-800 mb-2">
                  Shortened URL:
                </h3>
                <div className="flex items-center space-x-2 mb-3">
                  <input
                    type="text"
                    value={shortenedUrl}
                    readOnly
                    className="flex-1 px-3 py-2 border border-green-300 rounded text-sm bg-white"
                  />
                  <button
                    onClick={copyToClipboard}
                    className="px-4 py-2 bg-green-600 text-white rounded text-sm hover:bg-green-700 transition-colors"
                  >
                    Copy
                  </button>
                </div>
                
                {/* Visit Count Display */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <span className="text-sm text-green-700">
                      <strong>Visits:</strong> {visitCount !== null ? visitCount : 'Loading...'}
                    </span>
                    <button
                      onClick={refreshVisitCount}
                      className="px-3 py-1 bg-blue-100 text-blue-700 rounded text-xs hover:bg-blue-200 transition-colors"
                    >
                      Refresh Count
                    </button>
                  </div>
                  
                  {/* Test Visit Button */}
                  <button
                    onClick={testVisitCounting}
                    disabled={testingVisits}
                    className="px-3 py-1 bg-yellow-100 text-yellow-700 rounded text-xs hover:bg-yellow-200 transition-colors disabled:opacity-50"
                  >
                    {testingVisits ? 'Testing...' : 'Test Visit'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Device Info */}
          {fingerprint && (
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Device Information
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="font-medium text-gray-700">Visitor ID:</span>
                  <span className="ml-2 text-gray-600 font-mono">
                    {fingerprint.visitor_id.substring(0, 8)}...
                  </span>
                </div>
                <div>
                  <span className="font-medium text-gray-700">Risk Score:</span>
                  <span className={`ml-2 px-2 py-1 rounded text-xs font-medium ${
                    fingerprint.risk_score === 0 ? 'bg-green-100 text-green-800' :
                    fingerprint.risk_score <= 3 ? 'bg-yellow-100 text-yellow-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {fingerprint.risk_score}/10
                  </span>
                </div>
                <div>
                  <span className="font-medium text-gray-700">Created:</span>
                  <span className="ml-2 text-gray-600">
                    {new Date(fingerprint.created_at).toLocaleDateString()}
                  </span>
                </div>
                <div>
                  <span className="font-medium text-gray-700">Browser:</span>
                  <span className="ml-2 text-gray-600">
                    {fingerprint.browser_info?.userAgent?.split(' ')[0] || 'Unknown'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Setup Instructions */}
          {!fingerprint && (
            <div id="setup" className="bg-white rounded-lg shadow-lg p-6 mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                🚀 Set Up Supabase for Full Functionality
              </h3>
              <div className="space-y-4 text-sm text-gray-700">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">1. Create Supabase Project</h4>
                  <p>Go to <a href="https://supabase.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">supabase.com</a> and create a new project</p>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">2. Get Your Credentials</h4>
                  <p>In your project dashboard, go to Settings → API and copy:</p>
                  <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                    <li>Project URL</li>
                    <li>anon/public key</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">3. Update Environment Variables</h4>
                  <p>Update your <code className="bg-gray-100 px-1 rounded">.env</code> file:</p>
                  <pre className="bg-gray-100 p-3 rounded mt-2 text-xs overflow-x-auto">
{`REACT_APP_SUPABASE_URL=https://your-project-id.supabase.co
REACT_APP_SUPABASE_ANON_KEY=your-anon-key-here`}
                  </pre>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">4. Run Database Schema</h4>
                  <p>In your Supabase SQL editor, run the schema from <code className="bg-gray-100 px-1 rounded">supabase-complete-schema.sql</code></p>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">5. Restart the App</h4>
                  <p>Restart the development server to load the new environment variables</p>
                </div>
              </div>
            </div>
          )}

          {/* Admin Link */}
          <div className="text-center mt-6">
            <a
              href="/admin"
              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              Admin Dashboard →
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}

export default UrlShortener
