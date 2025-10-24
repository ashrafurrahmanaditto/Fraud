import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { supabase, Url } from '../lib/supabase'
import { getOrCreateFingerprint, logUrlVisit } from '../lib/fingerprint'
import toast from 'react-hot-toast'

const RedirectHandler: React.FC = () => {
  const { shortCode } = useParams<{ shortCode: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const handleRedirect = async () => {
      if (!shortCode) {
        setError('Invalid short code')
        setLoading(false)
        return
      }

      try {
        // Get the URL from database
        const { data: urlData, error: urlError } = await supabase
          .from('urls')
          .select('*')
          .eq('short_code', shortCode)
          .single()

        if (urlError || !urlData) {
          setError('URL not found')
          setLoading(false)
          return
        }

        // Check if URL has expired
        if (urlData.expires_at && new Date(urlData.expires_at) < new Date()) {
          setError('This URL has expired')
          setLoading(false)
          return
        }

        // Get fingerprint for tracking
        const fingerprint = await getOrCreateFingerprint()
        
        // Log the visit
        if (fingerprint) {
          await logUrlVisit(urlData.id, fingerprint.id)
        }

        // Update click count
        await supabase
          .from('urls')
          .update({ click_count: urlData.click_count + 1 })
          .eq('id', urlData.id)

        // Redirect to original URL
        window.location.href = urlData.original_url

      } catch (error) {
        console.error('Error handling redirect:', error)
        setError('An error occurred while redirecting')
        setLoading(false)
      }
    }

    handleRedirect()
  }, [shortCode])

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Redirecting...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-500 text-6xl mb-4">⚠️</div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">Error</h1>
          <p className="text-gray-600 mb-6">{error}</p>
          <button
            onClick={() => navigate('/')}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Go Home
          </button>
        </div>
      </div>
    )
  }

  return null
}

export default RedirectHandler
