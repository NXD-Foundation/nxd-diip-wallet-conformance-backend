/**
 * Unit tests for routes/didweb.js
 *
 * Tests the DID document structure added for did:web, including:
 * - Full DID URLs in verificationMethod.id, authentication, and assertionMethod (per did:web spec)
 * - assertionMethod present for credential signing
 * - Path-based DIDs (e.g. /diipv5/did.json, /rfc-issuer/did.json)
 * - JWKS kid as full did#keys-1
 *
 * Requires ./didjwks/did_public.pem to exist (same as production).
 */
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';

// SERVER_URL and PROXY_PATH are read at router load time. Use delete so PROXY_PATH is
// undefined (setting to null would make process.env.PROXY_PATH the string "null").
const originalServerUrl = process.env.SERVER_URL;
const originalProxyPath = process.env.PROXY_PATH;

process.env.SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
delete process.env.PROXY_PATH;

const didWebRouter = (await import('../routes/didweb.js')).default;

const app = express();
app.use('/', didWebRouter);

function restoreEnv() {
  if (originalServerUrl !== undefined) process.env.SERVER_URL = originalServerUrl;
  else delete process.env.SERVER_URL;
  if (originalProxyPath !== undefined) process.env.PROXY_PATH = originalProxyPath;
  else delete process.env.PROXY_PATH;
}

describe('DID Web routes', () => {
  after(() => {
    restoreEnv();
  });

  describe('GET /.well-known/did.json and GET /did.json', () => {
    const endpoints = ['/.well-known/did.json', '/did.json'];

    endpoints.forEach((endpoint) => {
      describe(endpoint, () => {
        it('returns 200 and a valid DID document', async () => {
          const res = await request(app).get(endpoint).expect(200);
          expect(res.body).to.have.property('@context', 'https://www.w3.org/ns/did/v1');
          expect(res.body).to.have.property('id');
          expect(res.body.id).to.match(/^did:web:/);
          expect(res.body).to.have.property('verificationMethod').that.is.an('array');
          expect(res.body.verificationMethod).to.have.lengthOf(1);
          expect(res.body).to.have.property('authentication').that.is.an('array');
          expect(res.body).to.have.property('assertionMethod').that.is.an('array');
          expect(res.body).to.have.property('service').that.is.an('array');
        });

        it('uses full DID URL for verificationMethod.id (did:web:...)#keys-1)', async () => {
          const res = await request(app).get(endpoint).expect(200);
          const vm = res.body.verificationMethod[0];
          expect(vm.id).to.match(/^did:web:.+#keys-1$/);
          expect(vm.id).to.equal(res.body.id + '#keys-1');
        });

        it('uses full DID for verificationMethod.controller', async () => {
          const res = await request(app).get(endpoint).expect(200);
          const vm = res.body.verificationMethod[0];
          expect(vm.controller).to.equal(res.body.id);
          expect(vm.controller).to.match(/^did:web:/);
        });

        it('authentication and assertionMethod reference match verificationMethod.id', async () => {
          const res = await request(app).get(endpoint).expect(200);
          const keyId = res.body.verificationMethod[0].id;
          expect(res.body.authentication).to.deep.equal([keyId]);
          expect(res.body.assertionMethod).to.deep.equal([keyId]);
        });

        it('service entry has id as full DID#jwks and type JsonWebKey2020', async () => {
          const res = await request(app).get(endpoint).expect(200);
          const service = res.body.service.find((s) => s.id && s.id.endsWith('#jwks'));
          expect(service).to.exist;
          expect(service.id).to.equal(res.body.id + '#jwks');
          expect(service.type).to.equal('JsonWebKey2020');
          expect(service).to.have.property('serviceEndpoint');
        });

        it('verificationMethod contains publicKeyJwk', async () => {
          const res = await request(app).get(endpoint).expect(200);
          const vm = res.body.verificationMethod[0];
          expect(vm).to.have.property('publicKeyJwk');
          expect(vm.publicKeyJwk).to.have.property('kty');
          expect(vm.publicKeyJwk).to.have.property('crv');
        });
      });
    });
  });

  describe('GET /:path/did.json (path-based DIDs)', () => {
    it('returns 200 for /diipv5/did.json with id did:web:<controller>:diipv5', async () => {
      const res = await request(app).get('/diipv5/did.json').expect(200);
      expect(res.body.id).to.match(/^did:web:.+:diipv5$/);
      expect(res.body.id).to.equal('did:web:localhost:3000:diipv5');
    });

    it('returns 200 for /rfc-issuer/did.json with id did:web:<controller>:rfc-issuer', async () => {
      const res = await request(app).get('/rfc-issuer/did.json').expect(200);
      expect(res.body.id).to.match(/^did:web:.+:rfc-issuer$/);
      expect(res.body.id).to.equal('did:web:localhost:3000:rfc-issuer');
    });

    it('path-based DID has key references matching verificationMethod.id', async () => {
      const res = await request(app).get('/diipv5/did.json').expect(200);
      const keyId = res.body.verificationMethod[0].id;
      expect(keyId).to.equal(res.body.id + '#keys-1');
      expect(res.body.authentication).to.deep.equal([keyId]);
      expect(res.body.assertionMethod).to.deep.equal([keyId]);
    });

    it('path-based DID verificationMethod.controller is full DID', async () => {
      const res = await request(app).get('/diipv5/did.json').expect(200);
      expect(res.body.verificationMethod[0].controller).to.equal(res.body.id);
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('returns 200 and a keys array', async () => {
      const res = await request(app).get('/.well-known/jwks.json').expect(200);
      expect(res.body).to.have.property('keys').that.is.an('array');
      expect(res.body.keys.length).to.be.at.least(1);
    });

    it('each key has kid as full DID URL (did:web:...#keys-1)', async () => {
      const res = await request(app).get('/.well-known/jwks.json').expect(200);
      const key = res.body.keys[0];
      expect(key).to.have.property('kid');
      expect(key.kid).to.match(/^did:web:.+#keys-1$/);
    });

    it('kid matches root DID document key id for same server', async () => {
      const [docRes, jwksRes] = await Promise.all([
        request(app).get('/.well-known/did.json'),
        request(app).get('/.well-known/jwks.json'),
      ]);
      const expectedKeyId = docRes.body.verificationMethod[0].id;
      expect(jwksRes.body.keys[0].kid).to.equal(expectedKeyId);
      expect(docRes.body.id).to.not.include('http://');
      expect(docRes.body.id).to.not.include('https://');
    });
  });
});
