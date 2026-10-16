import { jwtVerify, SignJWT } from 'jose';
import { loadConfig } from '../config.js';

const ISSUER = 'imoveladmin';
const AUDIENCE = 'imoveladmin-api';
export const ACCESS_TOKEN_TTL_SECONDS = 10 * 60;

export interface AccessClaims {
  sub: string;
  sid: string;
}

function secret(): Uint8Array {
  return new TextEncoder().encode(loadConfig().JWT_SECRET);
}

export async function signAccessToken(claims: AccessClaims, ttlSeconds = ACCESS_TOKEN_TTL_SECONDS): Promise<string> {
  return new SignJWT({ sid: claims.sid })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(claims.sub)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(secret());
}

export async function verifyAccessToken(token: string): Promise<AccessClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secret(), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });
    if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string') return null;
    return { sub: payload.sub, sid: payload.sid };
  } catch {
    return null;
  }
}
