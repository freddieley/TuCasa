import { withSupabase } from 'npm:@supabase/server@^1'
import { corsHeaders } from 'npm:@supabase/supabase-js@2/cors'

const USERNAME_RE = /^[a-z0-9_]{3,24}$/
const AUTH_DOMAIN = 'tucasa-phi.vercel.app'

const response = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: corsHeaders })

export default {
  fetch: withSupabase({ auth: 'none' }, async (req, ctx) => {
    if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
    if (req.method !== 'POST') return response({ error: 'Method not allowed' }, 405)
    try {
      const body = await req.json()
      const username = String(body.username ?? '').trim().toLowerCase()
      const displayName = String(body.displayName ?? '').trim()
      const password = String(body.password ?? '')
      if (!USERNAME_RE.test(username)) return response({ error: 'Username must be 3–24 characters and use lowercase letters, numbers or underscores.' }, 400)
      if (displayName.length < 1 || displayName.length > 60) return response({ error: 'Display name must be between 1 and 60 characters.' }, 400)
      if (password.length < 8) return response({ error: 'Password must be at least 8 characters.' }, 400)
      const { data: existing, error: lookupError } = await ctx.supabaseAdmin.from('profiles').select('id').eq('username', username).maybeSingle()
      if (lookupError) return response({ error: lookupError.message }, 500)
      if (existing) return response({ error: 'That username is already taken.' }, 409)
      const { data: created, error: authError } = await ctx.supabaseAdmin.auth.admin.createUser({
        email: username + '@' + AUTH_DOMAIN,
        password,
        email_confirm: true,
      })
      if (authError || !created.user) return response({ error: authError?.message ?? 'Could not create account.' }, 400)
      const { error: profileError } = await ctx.supabaseAdmin.from('profiles').insert({
        id: created.user.id,
        username,
        display_name: displayName,
      })
      if (profileError) return response({ error: profileError.code === '23505' ? 'That username is already taken.' : profileError.message }, profileError.code === '23505' ? 409 : 400)
      return response({ ok: true, username })
    } catch (error) {
      console.error(error)
      return response({ error: error instanceof Error ? error.message : 'Invalid request.' }, 400)
    }
  }),
}
