// src/index.ts
import dotenv from 'dotenv';
dotenv.config();
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import jwt, { JwtPayload } from 'jsonwebtoken';
import type { Secret } from 'jsonwebtoken';
import axios from 'axios';
import { createClient } from '@supabase/supabase-js';

const {
  PORT = '8080',
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE,
  APP_JWT_SECRET,
  APP_JWT_ISSUER = 'uso-auth',
  APP_JWT_AUDIENCE = 'uso-app',
  APP_CORS_ORIGINS = '*',
} = process.env;

const APP_SECRET = (APP_JWT_SECRET ?? '') as Secret;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE || !APP_JWT_SECRET) {
  // 필수 ENV 누락 시 즉시 종료
  // Render 배포 로그에서 바로 원인 보이게 함
  console.error('ENV missing: SUPABASE_URL | SUPABASE_SERVICE_ROLE | APP_JWT_SECRET');
  process.exit(1);
}

const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const app = express();
app.use(express.json());
const origins = APP_CORS_ORIGINS.split(',').map(s => s.trim());
app.use(cors({ origin: origins.includes('*') ? true : origins }));

// 헬스체크
app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));

// 내 JWT 발급
app.post('/auth/kakao', async (req: Request, res: Response) => {
  try {
    const accessToken = req.body?.access_token as string | undefined;
    if (!accessToken) return res.status(400).json({ error: 'missing access_token' });

    const r = await axios.get('https://kapi.kakao.com/v2/user/me?secure_resource=true', {
      headers: { Authorization: `Bearer ${accessToken}` },
      validateStatus: () => true,
    });
    if (r.status !== 200) {
      return res.status(401).json({ error: 'kakao_invalid', detail: r.data });
    }
    const kakao = r.data as any;
    const kakaoId: string = String(kakao.id);

    const nowSec = Math.floor(Date.now() / 1000);
    const token = jwt.sign(
      {
        sub: `kakao:${kakaoId}`,
        provider: 'kakao',
        kakao_id: kakaoId,
        iat: nowSec,
        iss: APP_JWT_ISSUER,
        aud: APP_JWT_AUDIENCE,
      },
      APP_SECRET,
      { algorithm: 'HS256', expiresIn: '30d' }
    );

    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// JWT 검사
function requireJwt(req: Request & { user?: JwtPayload | string }, res: Response, next: NextFunction) {
  try {
    const hdr = req.headers.authorization || '';
    const m = hdr.match(/^Bearer (.+)$/i);
    if (!m) return res.status(401).json({ error: 'no_auth' });
    const payload = jwt.verify(m[1], APP_SECRET, {
      algorithms: ['HS256'],
      issuer: APP_JWT_ISSUER,
      audience: APP_JWT_AUDIENCE,
    });
    req.user = payload as JwtPayload;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Supabase upsert
app.post('/members/upsert', requireJwt, async (req: Request & { user?: any }, res: Response) => {
  try {
    const kakaoAccessToken = req.body?.kakao_access_token as string | undefined;
    if (!kakaoAccessToken) return res.status(400).json({ error: 'missing kakao_access_token' });

    const r = await axios.get('https://kapi.kakao.com/v2/user/me?secure_resource=true', {
      headers: { Authorization: `Bearer ${kakaoAccessToken}` },
      validateStatus: () => true,
    });
    if (r.status !== 200) {
      return res.status(401).json({ error: 'kakao_invalid', detail: r.data });
    }
    const data = r.data as any;

    const acc = data.kakao_account ?? {};
    const profile = acc.profile ?? {};
    const kakaoId: string = String(data.id);

    const birthyear = acc.birthyear ? parseInt(acc.birthyear, 10) : null;
    const birthday = acc.birthday ?? null; // 'MMDD'
    let birthdate: string | null = null;
    if (birthyear && birthday && String(birthday).length === 4) {
      const mm = String(birthday).slice(0, 2);
      const dd = String(birthday).slice(2, 4);
      birthdate = `${birthyear}-${mm}-${dd}`;
    }

    const row = {
      provider: 'kakao',
      provider_user_id: kakaoId,
      email: acc.email ?? null,
      name: acc.name ?? null,
      nickname: profile.nickname ?? 'Guest',
      phone: acc.phone_number ?? null,
      avatar_url: profile.profile_image_url ?? null,
      gender: acc.gender ?? null,
      age_range: acc.age_range ?? null,
      birthyear,
      birthday,
      birthdate,
    };

    const { data: up, error } = await supa
      .from('members')
      .upsert(row, { onConflict: 'provider,provider_user_id' })
      .select()
      .limit(1);

    if (error) return res.status(500).json({ error: 'supabase_error', detail: error.message });
    res.json({ ok: true, member: up?.[0] ?? row });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// 내 프로필 조회(옵션)
app.get('/me', requireJwt, async (req: Request & { user?: any }, res: Response) => {
  try {
    const kakaoId = req.user?.kakao_id as string;
    const { data, error } = await supa
      .from('members')
      .select('*')
      .eq('provider', 'kakao')
      .eq('provider_user_id', kakaoId)
      .limit(1);
    if (error) return res.status(500).json({ error: 'supabase_error', detail: error.message });
    res.json({ member: data?.[0] ?? null });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

app.listen(parseInt(PORT, 10), () => {
  console.log(`uso-auth listening on :${PORT}`);
});
