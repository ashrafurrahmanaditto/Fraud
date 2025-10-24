// Enhanced Fraud Detection with ML Libraries
import { kmeans } from 'ml-kmeans'

export interface MLFraudDetectionResult {
  isFraudulent: boolean
  confidence: number
  riskScore: number
  anomalies: string[]
  mlScore: number
  botSignals: string[]
}

export class MLFraudDetector {
  private static instance: MLFraudDetector
  private normalPatterns: any[] = []
  private isModelTrained: boolean = false

  public static getInstance(): MLFraudDetector {
    if (!MLFraudDetector.instance) {
      MLFraudDetector.instance = new MLFraudDetector()
    }
    return MLFraudDetector.instance
  }

  // Extract features from fingerprint data
  private extractFeatures(fingerprintData: any): number[] {
    const features = [
      // Browser features
      fingerprintData.hardwareConcurrency || 0,
      fingerprintData.deviceMemory || 0,
      fingerprintData.touchSupport ? 1 : 0,
      fingerprintData.mobile ? 1 : 0,
      
      // Automation signals
      fingerprintData.webdriver ? 1 : 0,
      fingerprintData.phantom ? 1 : 0,
      fingerprintData.selenium ? 1 : 0,
      fingerprintData.headless ? 1 : 0,
      fingerprintData.automation ? 1 : 0,
      fingerprintData.gologin ? 1 : 0,
      fingerprintData.puppeteer ? 1 : 0,
      fingerprintData.playwright ? 1 : 0,
      
      // Timing features
      performance.now(),
      Date.now() % 1000, // Random timing component
      
      // Screen features
      window.screen.width,
      window.screen.height,
      window.screen.colorDepth,
      
      // Navigator features
      navigator.language.length,
      navigator.platform.length,
      navigator.userAgent.length,
      
      // Plugin count
      navigator.plugins.length,
      
      // Canvas fingerprinting resistance
      this.getCanvasFingerprintScore(),
      
      // WebGL features
      this.getWebGLScore(),
      
      // Audio context features
      this.getAudioContextScore()
    ]
    
    return features
  }

  // Get canvas fingerprinting score
  private getCanvasFingerprintScore(): number {
    try {
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (!ctx) return 0
      
      ctx.textBaseline = 'top'
      ctx.font = '14px Arial'
      ctx.fillText('test', 2, 2)
      
      const imageData = ctx.getImageData(0, 0, 100, 100)
      const data = imageData.data
      
      // Calculate entropy of canvas data
      let entropy = 0
      const histogram = new Array(256).fill(0)
      
      for (let i = 0; i < data.length; i += 4) {
        histogram[data[i]]++
      }
      
      for (let i = 0; i < 256; i++) {
        if (histogram[i] > 0) {
          const p = histogram[i] / (data.length / 4)
          entropy -= p * Math.log2(p)
        }
      }
      
      return entropy
    } catch (e) {
      return 0
    }
  }

  // Get WebGL score
  private getWebGLScore(): number {
    try {
      const canvas = document.createElement('canvas')
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl') as WebGLRenderingContext
      if (!gl) return 0
      
      const renderer = gl.getParameter(gl.RENDERER)
      const vendor = gl.getParameter(gl.VENDOR)
      
      return (renderer + vendor).length
    } catch (e) {
      return 0
    }
  }

  // Get audio context score
  private getAudioContextScore(): number {
    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext
      if (!AudioContext) return 0
      
      const audioContext = new AudioContext()
      const oscillator = audioContext.createOscillator()
      const analyser = audioContext.createAnalyser()
      
      oscillator.connect(analyser)
      oscillator.start()
      
      const bufferLength = analyser.frequencyBinCount
      const dataArray = new Uint8Array(bufferLength)
      analyser.getByteFrequencyData(dataArray)
      
      oscillator.stop()
      audioContext.close()
      
      return dataArray.reduce((sum, val) => sum + val, 0)
    } catch (e) {
      return 0
    }
  }

  // Train the ML model with normal patterns
  public async trainModel(normalFingerprints: any[]): Promise<void> {
    if (normalFingerprints.length < 10) {
      console.warn('Not enough data to train model')
      return
    }

    try {
      // Extract features from normal fingerprints
      const features = normalFingerprints.map(fp => this.extractFeatures(fp))
      
      // Store normal patterns for distance-based detection
      this.normalPatterns = features
      this.isModelTrained = true
      
      console.log('ML fraud detection model trained successfully')
    } catch (error) {
      console.error('Error training ML model:', error)
    }
  }

  // Detect anti-detect browsers specifically
  private detectAntiDetectBrowser(fingerprintData: any): string[] {
    const signals: string[] = []
    
    // Check for GoLogin specific indicators
    if (fingerprintData.gologin) {
      signals.push('gologin_detected')
    }
    
    // Check for stealth mode
    if (fingerprintData.stealthMode) {
      signals.push('stealth_mode')
    }
    
    // Check for automation signals
    if (fingerprintData.automationSignals && fingerprintData.automationSignals.length > 0) {
      signals.push('automation_signals')
    }
    
    // Check for suspicious browser properties
    if (!navigator.permissions) signals.push('no_permissions')
    if (!navigator.mediaDevices) signals.push('no_media_devices')
    if (navigator.plugins.length === 0) signals.push('no_plugins')
    
    // Check for suspicious hardware
    if (navigator.hardwareConcurrency === 0) signals.push('no_hardware_concurrency')
    if ((navigator as any).deviceMemory === 0) signals.push('no_device_memory')
    
    // Check for timing anomalies
    if (performance.now() < 100) signals.push('suspicious_timing')
    
    return signals
  }

  // Detect fraud using ML and bot detection
  public async detectFraud(fingerprintData: any): Promise<MLFraudDetectionResult> {
    const features = this.extractFeatures(fingerprintData)
    const anomalies: string[] = []
    let mlScore = 0
    let riskScore = 0
    let confidence = 0

    // Bot detection using custom heuristics
    const botSignals: string[] = []
    try {
      // Custom bot detection heuristics
      if (fingerprintData.webdriver) {
        botSignals.push('webdriver_detected')
        riskScore += 2
      }
      
      if (fingerprintData.automation) {
        botSignals.push('automation_detected')
        riskScore += 2
      }
      
      if (fingerprintData.headless) {
        botSignals.push('headless_detected')
        riskScore += 2
      }
      
      if (fingerprintData.gologin) {
        botSignals.push('gologin_detected')
        riskScore += 5  // Higher risk score for GoLogin
      }
      
      if (fingerprintData.puppeteer) {
        botSignals.push('puppeteer_detected')
        riskScore += 3
      }
      
      if (fingerprintData.playwright) {
        botSignals.push('playwright_detected')
        riskScore += 3
      }
      
      // Check for missing browser features that bots often lack
      if (!navigator.permissions) {
        botSignals.push('missing_permissions')
        riskScore += 1
      }
      
      if (!navigator.mediaDevices) {
        botSignals.push('missing_media_devices')
        riskScore += 1
      }
      
      // Check for suspicious timing patterns
      const timing = performance.now()
      if (timing < 50) {
        botSignals.push('suspicious_timing')
        riskScore += 1
      }
      
      // Check for automation signals array
      if (fingerprintData.automationSignals && fingerprintData.automationSignals.length > 0) {
        botSignals.push(...fingerprintData.automationSignals)
        riskScore += fingerprintData.automationSignals.length
      }
      
    } catch (error) {
      console.error('Bot detection error:', error)
    }

    // ML-based anomaly detection
    if (this.isModelTrained) {
      try {
        let minDistance = Infinity
        
        // Calculate distance to nearest normal pattern
        for (const pattern of this.normalPatterns) {
          const distance = this.calculateDistance(features, pattern)
          minDistance = Math.min(minDistance, distance)
        }
        
        // Convert distance to anomaly score (0-1)
        mlScore = Math.min(minDistance / 100, 1) // Normalize distance
        
        if (mlScore > 0.7) {
          anomalies.push('ml_anomaly_detected')
          riskScore += 4
          confidence += 0.6
        }
      } catch (error) {
        console.error('ML detection error:', error)
      }
    }

    // Anti-detect browser detection
    const antiDetectSignals = this.detectAntiDetectBrowser(fingerprintData)
    botSignals.push(...antiDetectSignals)
    riskScore += antiDetectSignals.length * 3  // Higher weight for anti-detect signals
    
    // Rule-based anomaly detection
    const ruleBasedAnomalies = this.detectRuleBasedAnomalies(fingerprintData)
    anomalies.push(...ruleBasedAnomalies)
    riskScore += ruleBasedAnomalies.length * 2

    // Calculate final confidence
    confidence = Math.min(confidence + (anomalies.length * 0.1), 1)

    // Debug logging
    console.log('🔍 ML Fraud Detection Debug:', {
      riskScore,
      mlScore,
      botSignals,
      anomalies,
      isFraudulent: riskScore >= 3 || mlScore > 0.5 || botSignals.length > 0 || anomalies.length >= 2
    })

    return {
      isFraudulent: riskScore >= 5 || mlScore > 0.7 || botSignals.length > 2 || anomalies.length >= 3,
      confidence,
      riskScore,
      anomalies,
      mlScore,
      botSignals
    }
  }

  // Calculate Euclidean distance between two feature vectors
  private calculateDistance(features1: number[], features2: number[]): number {
    if (features1.length !== features2.length) return Infinity
    
    let sum = 0
    for (let i = 0; i < features1.length; i++) {
      sum += Math.pow(features1[i] - features2[i], 2)
    }
    
    return Math.sqrt(sum)
  }

  // Rule-based anomaly detection
  private detectRuleBasedAnomalies(fingerprintData: any): string[] {
    const anomalies: string[] = []

    // Check for suspicious hardware configurations
    if (fingerprintData.hardwareConcurrency === 0) {
      anomalies.push('no_hardware_concurrency')
    }
    
    if (fingerprintData.deviceMemory === 0) {
      anomalies.push('no_device_memory')
    }

    // Check for automation signals
    if (fingerprintData.webdriver || fingerprintData.selenium || fingerprintData.phantom) {
      anomalies.push('automation_detected')
    }
    
    // Enhanced anti-detect browser detection
    if (fingerprintData.gologin) {
      anomalies.push('anti_detect_browser')
    }
    
    // Check for stealth mode indicators
    if (fingerprintData.stealthMode) {
      anomalies.push('stealth_mode_detected')
    }
    
    // Check for automation signals array
    if (fingerprintData.automationSignals && fingerprintData.automationSignals.length > 0) {
      anomalies.push('multiple_automation_signals')
    }

    // Check for suspicious timing
    const timing = performance.now()
    if (timing < 50) {
      anomalies.push('suspicious_timing')
    }

    // Check for missing browser features
    if (!navigator.permissions) {
      anomalies.push('missing_permissions_api')
    }

    if (!navigator.mediaDevices) {
      anomalies.push('missing_media_devices_api')
    }

    // Check for canvas fingerprinting evasion
    if (this.getCanvasFingerprintScore() < 1) {
      anomalies.push('canvas_evasion')
    }

    return anomalies
  }

  // Get detection summary
  public getDetectionSummary(result: MLFraudDetectionResult): string {
    const parts = []
    
    if (result.botSignals.length > 0) {
      parts.push(`Bot signals: ${result.botSignals.join(', ')}`)
    }
    
    if (result.anomalies.length > 0) {
      parts.push(`Anomalies: ${result.anomalies.join(', ')}`)
    }
    
    if (result.mlScore > 0.5) {
      parts.push(`ML anomaly score: ${(result.mlScore * 100).toFixed(1)}%`)
    }
    
    return parts.join(' | ')
  }
}

// Export singleton instance
export const mlFraudDetector = MLFraudDetector.getInstance()
