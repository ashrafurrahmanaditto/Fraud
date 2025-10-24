// Enhanced FingerprintJS integration with full component capture
import FingerprintJS from '@fingerprintjs/fingerprintjs'
import { supabase } from './supabase'

let fpPromise: Promise<any> | null = null

// Enhanced automation detection methods
const detectGoLogin = () => {
  // Check for GoLogin specific indicators
  const indicators = [
    // Check for GoLogin specific properties
    !!(window as any).gologin,
    !!(window as any).gologinProfile,
    !!(window as any).gologinBrowser,
    // Check for modified navigator properties
    navigator.webdriver === false && (window as any).chrome && !(window as any).chrome.runtime,
    // Check for suspicious user agent patterns
    /GoLogin|Automation|Headless/i.test(navigator.userAgent),
    // Check for missing or modified properties
    !navigator.plugins || navigator.plugins.length === 0,
    // Check for timing inconsistencies
    performance.now() < 100
  ]
  
  return indicators.filter(Boolean).length >= 2
}

const detectPuppeteer = () => {
  const indicators = [
    !!(window as any).puppeteer,
    !!(window as any).__puppeteer,
    !!(window as any).__nightmare,
    !!(window as any).callPhantom,
    !!(window as any)._phantom,
    // Check for missing properties that Puppeteer often removes
    !navigator.permissions,
    !navigator.mediaDevices,
    // Check for suspicious timing
    performance.now() < 50
  ]
  
  return indicators.filter(Boolean).length >= 2
}

const detectPlaywright = () => {
  const indicators = [
    !!(window as any).playwright,
    !!(window as any).__playwright,
    // Check for Playwright specific properties
    !!(window as any).playwrightElectron,
    // Check for modified navigator
    navigator.webdriver === false && !navigator.permissions,
    // Check for suspicious patterns
    /Playwright|Electron/i.test(navigator.userAgent)
  ]
  
  return indicators.filter(Boolean).length >= 1
}

const detectStealthMode = () => {
  const indicators = [
    // Check for stealth mode indicators
    navigator.webdriver === false && (window as any).chrome && !(window as any).chrome.runtime,
    // Check for missing automation properties
    !(window as any).webdriver && !(navigator as any).webdriver,
    // Check for suspicious timing patterns
    performance.now() < 100 && performance.now() > 0,
    // Check for modified navigator properties
    navigator.plugins && navigator.plugins.length > 0 && !navigator.permissions,
    // Check for canvas fingerprinting evasion
    document.createElement('canvas').getContext('2d') && performance.now() < 200
  ]
  
  return indicators.filter(Boolean).length >= 3
}

const detectAdvancedAutomationSignals = () => {
  const signals = []
  
  // Check for automation frameworks
  if (!!(window as any).webdriver) signals.push('webdriver')
  if (!!(window as any).selenium) signals.push('selenium')
  if (!!(window as any).phantom) signals.push('phantom')
  if (!!(window as any).puppeteer) signals.push('puppeteer')
  if (!!(window as any).playwright) signals.push('playwright')
  if (!!(window as any).gologin) signals.push('gologin')
  
  // Check for headless indicators
  if (!navigator.permissions) signals.push('no_permissions')
  if (!navigator.mediaDevices) signals.push('no_media_devices')
  if (navigator.plugins.length === 0) signals.push('no_plugins')
  if (navigator.hardwareConcurrency === 0) signals.push('no_hardware_concurrency')
  if ((navigator as any).deviceMemory === 0) signals.push('no_device_memory')
  
  // Check for timing inconsistencies
  const timing = performance.now()
  if (timing < 50) signals.push('suspicious_timing')
  if (timing > 1000) signals.push('slow_timing')
  
  // Check for canvas fingerprinting evasion
  try {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    if (ctx) {
      ctx.textBaseline = 'top'
      ctx.font = '14px Arial'
      ctx.fillText('test', 2, 2)
      const imageData = ctx.getImageData(0, 0, 100, 100)
      if (imageData.data.every(pixel => pixel === 0)) {
        signals.push('canvas_evasion')
      }
    }
  } catch (e) {
    signals.push('canvas_error')
  }
  
  return signals
}

// Initialize FingerprintJS with enhanced configuration
export const initializeFingerprint = async () => {
  if (!fpPromise) {
    fpPromise = FingerprintJS.load({
      debug: process.env.NODE_ENV === 'development'
    })
  }
  return fpPromise
}

// Get comprehensive device fingerprint with all components
export const getDeviceFingerprint = async () => {
  try {
    const fp = await initializeFingerprint()
    const result = await fp.get()
    
    // Extract all components for detailed analysis
    const components = result.components
    console.log('FingerprintJS Components:', components) // Debug log
    
    const fingerprintData = {
      visitorId: result.visitorId,
      confidence: result.confidence,
      components: components,
      // Extract specific high-value components using correct property names
      canvas: components.canvas?.value,
      webgl: components.webgl?.value,
      audio: components.audio?.value,
      plugins: components.plugins?.value,
      timezone: components.timezone?.value,
      screenResolution: components.screenResolution?.value,
      hardwareConcurrency: components.hardwareConcurrency?.value || navigator.hardwareConcurrency || 0,
      deviceMemory: components.deviceMemory?.value || (navigator as any).deviceMemory || 0,
      touchSupport: components.touchSupport?.value || ('ontouchstart' in window),
      language: components.language?.value || navigator.language,
      userAgent: components.userAgent?.value || navigator.userAgent,
      platform: components.platform?.value || navigator.platform,
      mobile: components.mobile?.value || /Mobi|Android/i.test(navigator.userAgent),
      // Additional components for fraud detection
      webdriver: components.webdriver?.value || !!(window as any).webdriver || !!(navigator as any).webdriver,
      phantom: components.phantom?.value || !!(window as any).phantom || !!(window as any).callPhantom,
      selenium: components.selenium?.value || !!(window as any).selenium || !!(window as any).seleniumIDE,
      headless: components.headless?.value || !!(window as any).headless || !!(navigator as any).headless,
      automation: components.automation?.value || !!(window as any).automation || !!(navigator as any).automation,
      
      // Enhanced GoLogin and automation detection
      gologin: detectGoLogin(),
      puppeteer: detectPuppeteer(),
      playwright: detectPlaywright(),
      stealthMode: detectStealthMode(),
      automationSignals: detectAdvancedAutomationSignals(),
      // Browser-specific components
      chrome: components.chrome?.value || !!(window as any).chrome && !!(window as any).chrome.runtime,
      firefox: components.firefox?.value || !!(window as any).InstallTrigger,
      safari: components.safari?.value || /^((?!chrome|android).)*safari/i.test(navigator.userAgent),
      edge: components.edge?.value || /edge/i.test(navigator.userAgent),
      // Font detection
      fonts: components.fonts?.value,
      // Canvas fingerprinting
      canvasFingerprint: components.canvasFingerprint?.value,
      // WebRTC
      webrtc: components.webrtc?.value,
      // Battery API
      battery: components.battery?.value,
      // Connection info
      connection: components.connection?.value,
      // Media devices
      mediaDevices: components.mediaDevices?.value,
      // Permissions
      permissions: components.permissions?.value,
      // Storage
      localStorage: components.localStorage?.value,
      sessionStorage: components.sessionStorage?.value,
      indexedDB: components.indexedDB?.value,
      // Timing attacks
      timing: components.timing?.value,
      // All components as JSON for ML analysis
      allComponents: components
    }
    
    return fingerprintData
  } catch (error) {
    console.error('Error getting enhanced fingerprint:', error)
    return null
  }
}

// Get comprehensive browser and device info
export const getBrowserInfo = () => {
  const userAgent = navigator.userAgent
  const language = navigator.language
  const platform = navigator.platform
  const screenInfo = {
    width: window.screen.width,
    height: window.screen.height,
    colorDepth: window.screen.colorDepth,
    pixelDepth: window.screen.pixelDepth,
    availWidth: window.screen.availWidth,
    availHeight: window.screen.availHeight
  }
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone
  const cookieEnabled = navigator.cookieEnabled
  const doNotTrack = navigator.doNotTrack
  
  // Additional browser capabilities
  const capabilities = {
    webgl: !!window.WebGLRenderingContext,
    webgl2: !!window.WebGL2RenderingContext,
    webAudio: !!(window.AudioContext || (window as any).webkitAudioContext),
    webRTC: !!(window.RTCPeerConnection || (window as any).webkitRTCPeerConnection),
    geolocation: !!navigator.geolocation,
    notifications: !!window.Notification,
    serviceWorker: !!navigator.serviceWorker,
    pushManager: !!window.PushManager,
    indexedDB: !!window.indexedDB,
    localStorage: !!window.localStorage,
    sessionStorage: !!window.sessionStorage,
    webSQL: !!(window as any).openDatabase,
    touchEvents: 'ontouchstart' in window,
    pointerEvents: 'onpointerdown' in window,
    devicePixelRatio: window.devicePixelRatio || 1,
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: (navigator as any).deviceMemory || 0,
    connection: (navigator as any).connection || null,
    battery: (navigator as any).getBattery ? 'available' : 'unavailable',
    permissions: !!navigator.permissions,
    mediaDevices: !!navigator.mediaDevices,
    clipboard: !!navigator.clipboard,
    share: !!navigator.share,
    wakeLock: !!(navigator as any).wakeLock,
    bluetooth: !!(navigator as any).bluetooth,
    usb: !!(navigator as any).usb,
    serial: !!(navigator as any).serial,
    hid: !!(navigator as any).hid,
    nfc: !!(navigator as any).nfc,
    // Bot detection signals
    webdriver: !!(window as any).webdriver || !!(navigator as any).webdriver,
    phantom: !!(window as any).phantom || !!(window as any).callPhantom,
    selenium: !!(window as any).selenium || !!(window as any).seleniumIDE,
    headless: !!(window as any).headless || !!(navigator as any).headless,
    automation: !!(window as any).automation || !!(navigator as any).automation,
    // Browser-specific detection
    chrome: !!(window as any).chrome && !!(window as any).chrome.runtime,
    firefox: !!(window as any).InstallTrigger,
    safari: /^((?!chrome|android).)*safari/i.test(userAgent),
    edge: /edge/i.test(userAgent),
    ie: /msie|trident/i.test(userAgent),
    opera: /opera|opr/i.test(userAgent)
  }
  
  return {
    userAgent,
    language,
    platform,
    screen: screenInfo,
    timezone,
    cookieEnabled,
    doNotTrack,
    capabilities,
    timestamp: new Date().toISOString(),
    // Additional metadata
    referrer: document.referrer,
    url: window.location.href,
    protocol: window.location.protocol,
    host: window.location.host,
    pathname: window.location.pathname,
    search: window.location.search,
    hash: window.location.hash
  }
}

// Save enhanced fingerprint to database
export const saveFingerprint = async (fingerprintData: any) => {
  try {
    const browserInfo = getBrowserInfo()
    
    // Prepare comprehensive fingerprint data
    const fingerprintRecord = {
      visitor_id: fingerprintData.visitorId,
      browser_info: {
        ...browserInfo,
        confidence: fingerprintData.confidence
      },
      device_info: {
        // Core FingerprintJS components
        canvas: fingerprintData.canvas,
        webgl: fingerprintData.webgl,
        audio: fingerprintData.audio,
        plugins: fingerprintData.plugins,
        timezone: fingerprintData.timezone,
        screenResolution: fingerprintData.screenResolution,
        hardwareConcurrency: fingerprintData.hardwareConcurrency,
        deviceMemory: fingerprintData.deviceMemory,
        touchSupport: fingerprintData.touchSupport,
        language: fingerprintData.language,
        userAgent: fingerprintData.userAgent,
        platform: fingerprintData.platform,
        mobile: fingerprintData.mobile,
        // Bot detection components
        webdriver: fingerprintData.webdriver,
        phantom: fingerprintData.phantom,
        selenium: fingerprintData.selenium,
        headless: fingerprintData.headless,
        automation: fingerprintData.automation,
        // Browser-specific
        chrome: fingerprintData.chrome,
        firefox: fingerprintData.firefox,
        safari: fingerprintData.safari,
        edge: fingerprintData.edge,
        // Additional components
        fonts: fingerprintData.fonts,
        canvasFingerprint: fingerprintData.canvasFingerprint,
        webrtc: fingerprintData.webrtc,
        battery: fingerprintData.battery,
        connection: fingerprintData.connection,
        mediaDevices: fingerprintData.mediaDevices,
        permissions: fingerprintData.permissions,
        localStorage: fingerprintData.localStorage,
        sessionStorage: fingerprintData.sessionStorage,
        indexedDB: fingerprintData.indexedDB,
        timing: fingerprintData.timing,
        // All components for ML analysis
        allComponents: fingerprintData.allComponents
      },
      user_agent: fingerprintData.userAgent || browserInfo.userAgent,
      // Additional metadata for fraud detection
      ip_address: null, // Will be populated by Edge Functions
      risk_score: 0 // Will be calculated by risk scoring function
    }
    
    const { data, error } = await supabase
      .from('fingerprints')
      .upsert(fingerprintRecord, {
        onConflict: 'visitor_id'
      })
      .select()
      .single()

    if (error) {
      console.error('Error saving enhanced fingerprint:', error)
      return null
    }

    return data
  } catch (error) {
    console.error('Error saving enhanced fingerprint:', error)
    return null
  }
}

// Get or create fingerprint
export const getOrCreateFingerprint = async () => {
  try {
    const fingerprintData = await getDeviceFingerprint()
    if (!fingerprintData) {
      throw new Error('Failed to get fingerprint')
    }

    const savedFingerprint = await saveFingerprint(fingerprintData)
    return savedFingerprint
  } catch (error) {
    console.error('Error getting or creating fingerprint:', error)
    return null
  }
}

// Log URL visit with fingerprint
export const logUrlVisit = async (urlId: string, fingerprintId?: string) => {
  try {
    const browserInfo = getBrowserInfo()
    
    const { data, error } = await supabase
      .from('url_visits')
      .insert({
        url_id: urlId,
        fingerprint_id: fingerprintId,
        ip_address: null, // Will be handled by Supabase Edge Functions
        referrer: document.referrer || null,
        user_agent: browserInfo.userAgent
      })

    if (error) {
      console.error('Error logging visit:', error)
      return false
    }

    return true
  } catch (error) {
    console.error('Error logging visit:', error)
    return false
  }
}

// Check rate limit
export const checkRateLimit = async (fingerprintId: string, actionType: string) => {
  try {
    const { data, error } = await supabase.rpc('check_rate_limit', {
      fingerprint_uuid: fingerprintId,
      action_type_param: actionType,
      max_attempts: 10,
      window_minutes: 60
    })

    if (error) {
      console.error('Error checking rate limit:', error)
      return false
    }

    return data
  } catch (error) {
    console.error('Error checking rate limit:', error)
    return false
  }
}

// Log risk event
export const logRiskEvent = async (
  fingerprintId: string,
  riskType: string,
  description: string,
  severity: number = 1,
  metadata?: any
) => {
  try {
    const { data, error } = await supabase
      .from('risk_logs')
      .insert({
        fingerprint_id: fingerprintId,
        risk_type: riskType,
        description,
        severity,
        metadata
      })

    if (error) {
      console.error('Error logging risk event:', error)
      return false
    }

    return true
  } catch (error) {
    console.error('Error logging risk event:', error)
    return false
  }
}
