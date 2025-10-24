// Supabase Edge Functions for URL Shortener API
// Place these files in your Supabase project's supabase/functions/ directory

// supabase/functions/shorten-url/index.ts
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

    const { url, fingerprint_id } = await req.json()

    if (!url) {
      return new Response(
        JSON.stringify({ error: 'URL is required' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Validate URL
    try {
      new URL(url)
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid URL format' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Check rate limit
    if (fingerprint_id) {
      const { data: rateLimitOk } = await supabaseClient.rpc('check_rate_limit', {
        fingerprint_uuid: fingerprint_id,
        action_type_param: 'url_creation',
        max_attempts: 10,
        window_minutes: 60
      })

      if (!rateLimitOk) {
        return new Response(
          JSON.stringify({ error: 'Rate limit exceeded' }),
          { 
            status: 429, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
          }
        )
      }
    }

    // Generate short code
    const { data: shortCode } = await supabaseClient.rpc('generate_short_code')

    if (!shortCode) {
      return new Response(
        JSON.stringify({ error: 'Failed to generate short code' }),
        { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Create URL record
    const { data: urlRecord, error } = await supabaseClient
      .from('urls')
      .insert({
        original_url: url,
        short_code: shortCode,
        fingerprint_id: fingerprint_id,
        ip_address: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip')
      })
      .select()
      .single()

    if (error) {
      console.error('Error creating URL:', error)
      return new Response(
        JSON.stringify({ error: 'Failed to create short URL' }),
        { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const shortUrl = `${req.headers.get('origin') || 'https://your-domain.com'}/${shortCode}`

    return new Response(
      JSON.stringify({ 
        success: true,
        short_url: shortUrl,
        short_code: shortCode,
        original_url: url,
        created_at: urlRecord.created_at
      }),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('Error in shorten-url function:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})
