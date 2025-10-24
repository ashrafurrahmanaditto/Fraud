// supabase/functions/redirect-url/index.ts
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
    )

    const url = new URL(req.url)
    const shortCode = url.pathname.split('/').pop()

    if (!shortCode) {
      return new Response(
        JSON.stringify({ error: 'Short code is required' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get URL record
    const { data: urlRecord, error } = await supabaseClient
      .from('urls')
      .select('*')
      .eq('short_code', shortCode)
      .eq('is_active', true)
      .single()

    if (error || !urlRecord) {
      return new Response(
        JSON.stringify({ error: 'URL not found' }),
        { 
          status: 404, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Check if URL has expired
    if (urlRecord.expires_at && new Date(urlRecord.expires_at) < new Date()) {
      return new Response(
        JSON.stringify({ error: 'URL has expired' }),
        { 
          status: 410, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get fingerprint ID from request headers or query params
    const fingerprintId = req.headers.get('x-fingerprint-id') || url.searchParams.get('fp')

    // Log the visit
    const { error: visitError } = await supabaseClient
      .from('url_visits')
      .insert({
        url_id: urlRecord.id,
        fingerprint_id: fingerprintId,
        ip_address: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip'),
        referrer: req.headers.get('referer'),
        user_agent: req.headers.get('user-agent'),
        country: req.headers.get('cf-ipcountry'), // Cloudflare country header
        city: req.headers.get('cf-ipcity') // Cloudflare city header
      })

    if (visitError) {
      console.error('Error logging visit:', visitError)
    }

    // Update click count
    await supabaseClient
      .from('urls')
      .update({ click_count: urlRecord.click_count + 1 })
      .eq('id', urlRecord.id)

    // Redirect to original URL
    return new Response(null, {
      status: 302,
      headers: {
        ...corsHeaders,
        'Location': urlRecord.original_url,
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
    })

  } catch (error) {
    console.error('Error in redirect-url function:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})
