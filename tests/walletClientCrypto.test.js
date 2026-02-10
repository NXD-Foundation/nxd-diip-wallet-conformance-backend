import { expect } from "chai";
import {
  ensureOrCreateEcKeyPair,
  createDPoP,
  createWUA,
} from "../wallet-client/src/lib/crypto.js";
import {
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from "jose";

describe("wallet-client crypto utilities", () => {
  it("createWUA SHOULD set typ to 'key-attestation+jwt' and include jwk in header", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(null, "ES256");

    const wuaJwt = await createWUA({
      privateJwk,
      publicJwk,
      issuer: "did:jwk:test-issuer",
      audience: "https://issuer.example.com/credential",
      attestedKeys: [publicJwk],
      eudiWalletInfo: {
        general_info: {
          name: "Test Wallet Client",
          version: "1.0.0",
        },
        key_storage_info: {
          storage_type: "software",
          protection_level: "software",
        },
      },
      alg: "ES256",
      ttlHours: 1,
    });

    const header = decodeProtectedHeader(wuaJwt);
    expect(header).to.be.an("object");
    expect(header).to.have.property("typ", "key-attestation+jwt");
    expect(header).to.have.property("alg", "ES256");
    expect(header).to.have.property("jwk");
    expect(header.jwk).to.be.an("object");
  });

  it("createDPoP SHOULD produce a dpop+jwt header and include htm/htu claims", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(null, "ES256");
    const rawHtu = "https://issuer.example.com/token_endpoint/";

    const dpopJwt = await createDPoP({
      privateJwk,
      publicJwk,
      htu: rawHtu,
      htm: "POST",
      alg: "ES256",
    });

    const header = decodeProtectedHeader(dpopJwt);
    expect(header).to.be.an("object");
    expect(header).to.have.property("typ", "dpop+jwt");
    expect(header).to.have.property("alg", "ES256");
    expect(header).to.have.property("jwk");

    const key = await importJWK(privateJwk, "ES256");
    const { payload } = await jwtVerify(dpopJwt, key, { algorithms: ["ES256"] });

    expect(payload).to.have.property("htm", "POST");
    expect(payload).to.have.property("htu");
    // Normalized URI SHOULD not contain a fragment and SHOULD end with the endpoint path
    expect(payload.htu).to.be.a("string");
    expect(payload.htu.endsWith("/token_endpoint")).to.equal(true);
    expect(payload.htu.includes("#")).to.equal(false);
    expect(payload).to.not.have.property("ath");
  });

  it("createDPoP SHOULD include ath claim when provided", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(null, "ES256");
    const htu = "https://issuer.example.com/credential";
    const athValue = "test-access-token-hash";

    const dpopJwt = await createDPoP({
      privateJwk,
      publicJwk,
      htu,
      htm: "POST",
      ath: athValue,
      alg: "ES256",
    });

    const key = await importJWK(privateJwk, "ES256");
    const { payload } = await jwtVerify(dpopJwt, key, { algorithms: ["ES256"] });

    expect(payload).to.have.property("ath", athValue);
  });
});

