import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import axios from 'axios';
import { SignJWT } from 'jose';

const app = express();
app.use(express.json());
app.use(cors({ origin: ['http://localhost', 'capacitor://localhost'] }));

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'dev');
const PORT = Number(process.env.PORT || 8787);

app.get('/health', (_, res) => res.send('ok'));

app.post('/auth/kakao', async (req, res) => {
  try {
    const at = req.body?.access_token as string;
    if (!at) return res.status(400).json({ error: 'missing access_token' });

    await axios.get('https://kapi.kakao.com/v1/user/access_token_info', {
      headers: { Authorization: `Bearer ${at}` }, timeout: 5000,
    });
    const me = await axios.get('https://kapi.kakao.com/v2/user/me?secure_resource=true', {
      headers: { Authorization: `Bearer ${at}` }, timeout: 5000,
    });

    const jwt = await new SignJWT({ sub: String(me.data.id) })
      .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('7d')
      .sign(JWT_SECRET);

    res.json({ token: jwt, user: me.data });
  } catch (e:any) {
    res.status(401).json({ error: 'kakao_auth_failed', detail: e?.response?.data ?? String(e) });
  }
});

app.listen(PORT, () => console.log(`auth :${PORT}`));
