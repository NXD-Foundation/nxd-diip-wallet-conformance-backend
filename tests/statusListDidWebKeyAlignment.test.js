/**
 * Unit tests verifying that did:web credentials and status list tokens
 * are signed with the same key exposed in /.well-known/jwks.json.
 *
 * Requires ./didjwks/did_private_pkcs8.key and ./didjwks/did_public.pem to exist.
 * Requires Redis for status list persistence.
 */
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import fs from 'fs';
import * as jose from 'jose';

const originalServerUrl = process.env.SERVER_URL;
const originalIssuerSigType = process.env.ISSUER_SIGNATURE_TYPE;
const originalProxyPath = process.env.PROXY_PATH;

process.env.ALLOW_NO_REDIS = 'true';
process.env.SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
process.env.ISSUER_SIGNATURE_TYPE = 'did:web';
delete process.env.PROXY_PATH;

function restoreEnv() {
  if (originalServerUrl !== undefined) process.env.SERVER_URL = originalServerUrl;
  else delete process.env.SERVER_URL;
  if (originalIssuerSigType !== undefined) process.env.ISSUER_SIGNATURE_TYPE = originalIssuerSigType;
  else delete process.env.ISSUER_SIGNATURE_TYPE;
  if (originalProxyPath !== undefined) process.env.PROXY_PATH = originalProxyPath;
  else delete process.env.PROXY_PATH;
}

const didWebRouter = (await import('../routes/didweb.js')).default;
const statusListRouter = (await import('../routes/statusListRoutes.js')).default;
const statusListManager = (await import('../utils/statusListUtils.js')).default;

const app = express();
app.use(express.json());
app.use('/', didWebRouter);
app.use('/', statusListRouter);

function didJwksFilesExist() {
  try {
    fs.accessSync('./didjwks/did_private_pkcs8.key');
    fs.accessSync('./didjwks/did_public.pem');
    return true;
  } catch {
    return false;
  }
}

describe('Status list and did:web credential key alignment', () => {
  let statusListId;

  before(async function () {
    if (!didJwksFilesExist()) {
      this.skip();
    }
    // Wait for Redis/cache to be ready (statusListManager uses it)
    const cacheService = await import('../services/cacheServiceRedis.js');
    let attempts = 0;
    while (cacheService.client && !cacheService.client.isReady && attempts < 50) {
      await new Promise((r) => setTimeout(r, 100));
      attempts++;
    }
  });

  after(async () => {
    if (statusListId) {
      try {
        await statusListManager.deleteStatusList(statusListId);
      } catch (_) {}
    }
    restoreEnv();
  });

  it('status list token and did:web credential are signed with the same key as /.well-known/jwks.json', async function () {
    if (!didJwksFilesExist()) {
      this.skip();
    }

    // 1. Create aligned status list with did:web
    const createRes = await request(app)
      .post('/status-list/aligned')
      .send({ size: 100, bits: 1, session_type: 'did:web' })
      .expect(201);
    statusListId = createRes.body.id;
    expect(createRes.body.iss).to.match(/^did:web:/);
    expect(createRes.body.kid).to.match(/^did:web:.+#keys-1$/);

    // 2. Get status list token (did:web)
    const tokenRes = await request(app)
      .get(`/status-list/${statusListId}`)
      .query({ session_type: 'did:web', is_haip: 'false' })
      .expect(200);
    const statusListToken = tokenRes.text;

    // 3. Create a minimal did:web credential JWT (same key as credGenerationUtils for did:web)
    const privateKeyPem = fs.readFileSync('./didjwks/did_private_pkcs8.key', 'utf8');
    const privateKey = await jose.importPKCS8(privateKeyPem, 'ES256');
    const controller = 'localhost:3000';
    const did = `did:web:${controller}`;
    const kid = `${did}#keys-1`;
    const credentialPayload = {
      iss: did,
      sub: 'did:example:holder',
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: { id: 'did:example:holder' },
      },
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const credentialJwt = await new jose.SignJWT(credentialPayload)
      .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', kid })
      .sign(privateKey);

    // 4. Fetch JWKS from /.well-known/jwks.json
    const jwksRes = await request(app).get('/.well-known/jwks.json').expect(200);
    const jwks = jwksRes.body;
    expect(jwks.keys).to.be.an('array').with.lengthOf.at.least(1);

    const JWKS = jose.createLocalJWKSet(jwks);

    // 5. Verify status list token with JWKS
    const statusListVerified = await jose.jwtVerify(statusListToken, JWKS);
    expect(statusListVerified.protectedHeader.kid).to.equal(kid);
    expect(statusListVerified.payload.iss).to.equal(did);

    // 6. Verify credential JWT with JWKS
    const credentialVerified = await jose.jwtVerify(credentialJwt, JWKS);
    expect(credentialVerified.protectedHeader.kid).to.equal(kid);
    expect(credentialVerified.payload.iss).to.equal(did);

    // 7. Both use the same kid and verify with the same JWKS
    expect(statusListVerified.protectedHeader.kid).to.equal(credentialVerified.protectedHeader.kid);
  });
});
