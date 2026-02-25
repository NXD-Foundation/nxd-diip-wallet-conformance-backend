import { expect } from "chai";
import sinon from "sinon";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";

// Helper to build a minimal unsigned JWT with a custom header
function buildFakeProofJwt(header) {
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  // Minimal payload, we don't care about its contents for these tests
  const payloadB64 = Buffer.from(JSON.stringify({})).toString("base64url");
  return `${headerB64}.${payloadB64}.signature`;
}

describe("handleCredentialGenerationBasedOnFormat - SD-JWT typ header", () => {
  let issueStub;

  beforeEach(() => {
    issueStub = sinon.stub(SDJwtVcInstance.prototype, "issue").resolves(
      "mock-credential",
    );
  });

  afterEach(() => {
    sinon.restore();
  });

  it("uses VCDM_2_0_SD_JWT_CREDENTIAL_TYP_HEADER (vc+sd-jwt) for VCDM 2.0 SD-JWT credentials", async () => {
    const header = {
      // Minimal JWK so holder binding logic does not throw
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: "test-x",
        y: "test-y",
      },
    };
    const proofJwt = buildFakeProofJwt(header);

    const requestBody = {
      vct: "VerifiablePortableDocumentA1SDJWT",
      proofs: { jwt: [proofJwt] },
    };

    const sessionObject = {
      signatureType: "jwk",
      isHaip: false,
    };

    await handleCredentialGenerationBasedOnFormat(
      requestBody,
      sessionObject,
      "https://issuer.example.org",
      "vc+sd-jwt",
    );

    expect(issueStub.calledOnce).to.be.true;
    const headerArg = issueStub.firstCall.args[2]; // sdjwt.issue(payload, disclosureFrame, headerOptions)
    expect(headerArg).to.have.property("header");
    expect(headerArg.header).to.have.property("typ", "vc+sd-jwt");
    expect(headerArg.header).to.have.property("cty", "vc");
  });

  it("uses SDJWT_CREDENTIAL_TYP_HEADER (dc+sd-jwt) for plain SD-JWT credentials", async () => {
    const header = {
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: "test-x",
        y: "test-y",
      },
    };
    const proofJwt = buildFakeProofJwt(header);

    const requestBody = {
      vct: "VerifiablePortableDocumentA1SDJWT",
      proofs: { jwt: [proofJwt] },
    };

    const sessionObject = {
      signatureType: "jwk",
      isHaip: false,
    };

    await handleCredentialGenerationBasedOnFormat(
      requestBody,
      sessionObject,
      "https://issuer.example.org",
      "dc+sd-jwt",
    );

    expect(issueStub.calledOnce).to.be.true;
    const headerArg = issueStub.firstCall.args[2];
    expect(headerArg).to.have.property("header");
    expect(headerArg.header).to.have.property("typ", "dc+sd-jwt");
    // For plain SD-JWT, we do not expect a cty=vc header
    expect(headerArg.header).to.not.have.property("cty");
  });
});

