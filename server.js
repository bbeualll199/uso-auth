'use strict'
require('dotenv').config()
const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const { createClient } = require('@supabase/supabase-js')

const app = express()
app.use(express.json())
app.use(cors({ origin: (o, cb) => cb(null, true) }))

const {
  PORT = 8080,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE,
  APP_JWT_SECRET,
  APP_JWT_ISSUER = 'uso-auth',
  APP_JWT_AUDIENCE = 'uso-app'
} = process.env

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE || !APP_JWT_SECRET) {
  console.error('ENV missing: SUPABASE_URL | SUPABASE_SERVICE_ROLE | APP_JWT_SECRET')
  process.exit(1)
}

const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false, autoRefreshToken: false }
})

// 1) Kakao 토큰 -> 내 JWT
app.post('/auth/kakao', async (req, res) => {
  try {
    const accessToken = req.body?.access_token
    if (!accessToken) return res.status(400).json({ error: 'missing access_token' })

    const r = await fetch('https://kapi.kakao.com/v2/user/me?secure_resource=true', {
      headers: { Authorization: `Bearer ${accessToken}` }
    })
    if (!r.ok) return res.status(401).json({ error: 'kakao_invalid', detail: await r.text() })
    const kakao = await r.json()
    const kakaoId = String(kakao.id)

    const nowSec = Math.floor(Date.now() / 1000)
    const token = jwt.sign(
      { sub: `kakao:${kakaoId}`, provider: 'kakao', kakao_id: kakaoId, iat: nowSec, iss: APP_JWT_ISSUER, aud: APP_JWT_AUDIENCE },
      APP_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '30d' }
    )

    res.json({ token })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server_error' })
  }
})

// JWT 검사
function requireJwt(req, res, next) {
  try {
    const hdr = req.headers.authorization || ''
    const m = hdr.match(/^Bearer (.+)$/i)
    if (!m) return res.status(401).json({ error: 'no_auth' })
    const payload = jwt.verify(m[1], APP_JWT_SECRET, { algorithms: ['HS256'], issuer: APP_JWT_ISSUER, audience: APP_JWT_AUDIENCE })
    req.user = payload
    next()
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' })
  }
}

// 2) Supabase members upsert
app.post('/members/upsert', requireJwt, async (req, res) => {
  try {
    const kakaoAccessToken = req.body?.kakao_access_token
    if (!kakaoAccessToken) return res.status(400).json({ error: 'missing kakao_access_token' })

    const r = await fetch('https://kapi.kakao.com/v2/user/me?secure_resource=true', {
      headers: { Authorization: `Bearer ${kakaoAccessToken}` }
    })
    if (!r.ok) return res.status(401).json({ error: 'kakao_invalid', detail: await r.text() })
    const data = await r.json()

    const acc = data.kakao_account || {}
    const profile = acc.profile || {}
    const kakaoId = String(data.id)

    const by = acc.birthyear ? parseInt(acc.birthyear, 10) : null
    const bd = acc.birthday || null // MMDD
    let birthdate = null
    if (by && bd && bd.length === 4) birthdate = `${by}-${bd.slice(0,2)}-${bd.slice(2,4)}`

    const row = {
      provider: 'kakao',
      provider_user_id: kakaoId,
      email: acc.email || null,
      name: acc.name || null,
      nickname: profile.nickname || 'Guest',
      phone: acc.phone_number || null,
      avatar_url: profile.profile_image_url || null,
      gender: acc.gender || null,
      age_range: acc.age_range || null,
      birthyear: by,
      birthday: bd,
      birthdate
    }

    const { data: up, error } = await supa
      .from('members')
      .upsert(row, { onConflict: 'provider,provider_user_id' })
      .select()
      .limit(1)

    if (error) return res.status(500).json({ error: 'supabase_error', detail: error.message })
    res.json({ ok: true, member: up?.[0] || row })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server_error' })
  }
})

// 3) 내 프로필 조회(옵션)
app.get('/me', requireJwt, async (req, res) => {
  try {
    const kid = req.user.kakao_id
    const { data, error } = await supa
      .from('members')
      .select('*')
      .eq('provider', 'kakao')
      .eq('provider_user_id', kid)
      .limit(1)
    if (error) return res.status(500).json({ error: 'supabase_error', detail: error.message })
    res.json({ member: data?.[0] || null })
  } catch (e) {
    res.status(500).json({ error: 'server_error' })
  }
})

app.get('/health', (req, res) => res.json({ ok: true }))

app.listen(PORT, () => console.log(`uso-auth listening on :${PORT}`))
