#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair } from "./lib/crypto.js";
import { storeWalletCredentialByType } from "./lib/cache.js";
import { resolveCredentialRequestParams } from "./lib/vci.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function discoverIssuerMetadata(credentialIssuerBase) {
  const base = credentialIssuerBase.replace(/\/$/, "");
  // RFC: if credential_issuer contains a path, well-known URI keeps path suffix
  let origin, path;
  try {
    const u = new URL(base);
    origin = u.origin;
    path = u.pathname.replace(/\/$/, "");
  } catch {
    origin = base; path = "";
  }
  const candidates = [
    `${origin}/.well-known/openid-credential-issuer${path}`,
    `${base}/.well-known/openid-credential-issuer`,
  ];
  let meta = null; let lastErr = null;
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      if (res.ok) { meta = await res.json(); break; }
      lastErr = res.status;
    } catch (e) { lastErr = e.message || String(e); }
  }
  if (!meta) throw new Error(`Issuer metadata fetch error ${lastErr}`);
  // Normalize property names that can differ across specs/implementations
  if (!meta.credential_deferred_endpoint && meta.deferred_credential_endpoint) {
    meta.credential_deferred_endpoint = meta.deferred_credential_endpoint;
  }
  // Some issuers expose authorization_servers (array) instead of authorization_server
  if (!meta.authorization_server && Array.isArray(meta.authorization_servers) && meta.authorization_servers.length > 0) {
    meta.authorization_server = meta.authorization_servers[0];
  }
  return meta;
}

async function discoverAuthorizationServerMetadata(authorizationServerBase) {
  // RFC 8414: If issuer has path component, well-known is host + '/.well-known/oauth-authorization-server' + path
  const baseStr = authorizationServerBase.replace(/\/$/, "");
  let origin, path;
  try {
    const u = new URL(baseStr);
    origin = u.origin;
    path = u.pathname.replace(/\/$/, "");
  } catch {
    // Not a full URL, fallback to direct
    origin = baseStr;
    path = "";
  }

  const candidates = [
    `${origin}/.well-known/oauth-authorization-server${path}`,
    `${origin}/.well-known/openid-configuration${path}`,
    `${baseStr}/.well-known/oauth-authorization-server`,
    `${baseStr}/.well-known/openid-configuration`,
  ];

  let lastErr = null;
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      if (res.ok) { 
        return res.json(); 
      }
      lastErr = res.status;
    } catch (e) {
      lastErr = e.message || String(e);
    }
  }
  throw new Error(`AS metadata fetch error ${lastErr}`);
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option("issuer", { type: "string", default: "http://localhost:3000" })
    .option("offer", { type: "string", describe: "openid-credential-offer deep link" })
    .option("fetch-offer", { type: "string", describe: "issuer path to fetch an offer, e.g. /offer-no-code" })
    .option("credential", { type: "string", describe: "credential_configuration_id to request" })
    .option("key", { type: "string", describe: "path to EC P-256 private JWK file" })
    .option("poll-interval", { type: "number", default: 2000 })
    .option("poll-timeout", { type: "number", default: 30000 })
    .strict()
    .help()
    .parse();

  const issuerBase = argv.issuer.replace(/\/$/, "");

  const deepLink = argv.offer || (await getOfferDeepLink(issuerBase, argv["fetch-offer"], argv.credential));
  if (!deepLink) {
    console.error("No offer provided or fetched.");
    process.exit(1);
  }

  const offerConfig = await resolveOfferConfig(deepLink);
  const { credential_issuer, credential_configuration_ids, grants } = offerConfig;

  const configurationId = argv.credential || credential_configuration_ids?.[0];
  if (!configurationId) {
    console.error("No credential_configuration_id available in offer; use --credential");
    process.exit(1);
  }

  const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  if (!preAuthGrant) {
    console.error("Only pre-authorized_code is supported in this client.");
    process.exit(1);
  }

  const preAuthorizedCode = preAuthGrant["pre-authorized_code"]; // sessionId
  const txCode = preAuthGrant?.tx_code ? await promptTxCode(preAuthGrant.tx_code) : undefined;

  // Fetch issuer metadata to get token endpoint
  const apiBase = (credential_issuer || issuerBase).replace(/\/$/, "");
  const issuerMeta = await discoverIssuerMetadata(apiBase);
  let tokenEndpoint = issuerMeta.token_endpoint || null;
  // If token_endpoint is not in issuer metadata, try authorization server metadata per RFC 8414
  if (!tokenEndpoint && (issuerMeta.authorization_server || (Array.isArray(issuerMeta.authorization_servers) && issuerMeta.authorization_servers.length))) {
    const asBase = issuerMeta.authorization_server || issuerMeta.authorization_servers[0];
    try {
      const asMeta = await discoverAuthorizationServerMetadata(asBase);
      tokenEndpoint = asMeta.token_endpoint;
    } catch (e) {
      console.warn("AS metadata discovery failed:", e?.message || e);
    }
  }
  // If still not found and no authorization_server specified, try issuer's own OAuth well-known endpoints
  if (!tokenEndpoint && !issuerMeta.authorization_server && !(Array.isArray(issuerMeta.authorization_servers) && issuerMeta.authorization_servers.length)) {
    try {
      const asMeta = await discoverAuthorizationServerMetadata(apiBase);
      tokenEndpoint = asMeta.token_endpoint;
      console.log("tokenEndpoint discovered via issuer's OAuth metadata:", tokenEndpoint);
    } catch (e) {
      console.warn("Issuer OAuth metadata discovery failed:", e?.message || e);
    }
  }
  // Fallback to standard OAuth2 token endpoint
  tokenEndpoint = tokenEndpoint || `${apiBase}/token`;
  const tokenRes = await httpPostJson(tokenEndpoint, {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthorizedCode,
    ...(txCode ? { tx_code: txCode } : {}),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.json().catch(() => ({}));
    throw new Error(`Token error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  const requestContext = resolveCredentialRequestParams({ configurationId, tokenResponse: tokenBody });

  let c_nonce = tokenBody.c_nonce;
  if (!c_nonce) {
    const nonceEndpoint = issuerMeta.nonce_endpoint || `${apiBase}/nonce`;
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) {
      const err = await nonceRes.json().catch(() => ({}));
      throw new Error(`Nonce error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const noncePayload = await nonceRes.json();
    c_nonce = noncePayload.c_nonce;
  }

  // key management
  // Algorithm negotiation
  const supportedAlgs = issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || [];
  const preferredOrder = ["ES256", "ES384", "ES512", "EdDSA"];
  const selectedAlg = (Array.isArray(supportedAlgs) && supportedAlgs.length)
    ? (preferredOrder.find((a) => supportedAlgs.includes(a)) || supportedAlgs[0])
    : "ES256";

  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(argv.key, selectedAlg);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);

  // build proof JWT
  const aud = issuerMeta?.credential_issuer || apiBase;
  const proofJwt = await createProofJwt({
    privateJwk,
    publicJwk,
    audience: aud,
    nonce: c_nonce,
    typ: "openid4vci-proof+jwt",
    alg: selectedAlg,
  });

  // credential request - use endpoint from issuer metadata
  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  const credReq = {
    ...requestContext.requestPayload,
    proof: { proof_type: "jwt", jwt: proofJwt },
  };

  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(credReq),
  });

  if (credRes.status === 202) {
    //deferred issuance
    const { transaction_id } = await credRes.json();
    const start = Date.now();
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    while (Date.now() - start < argv["poll-timeout"]) {
      await sleep(argv["poll-interval"]);
      const defRes = await httpPostJson(deferredEndpoint, { transaction_id });
      if (defRes.ok) {
        const body = await defRes.json();
        // store credential and key-binding material using preAuthorizedCode as session key
        await storeWalletCredentialByType(requestContext.storageKey, {
          credential: body,
          keyBinding: { privateJwk, publicJwk, didJwk },
          metadata: { configurationId, credentialIdentifier: requestContext.credentialIdentifier, c_nonce },
        });
        console.log(JSON.stringify(body, null, 2));
        return;
      }
    }
    throw new Error("Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`Credential error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  const credBody = await credRes.json();
  // store credential and key-binding material using preAuthorizedCode as session key
  await storeWalletCredentialByType(requestContext.storageKey, {
    credential: credBody,
    keyBinding: { privateJwk, publicJwk, didJwk },
    metadata: { configurationId, credentialIdentifier: requestContext.credentialIdentifier, c_nonce },
  });
  console.log(JSON.stringify(credBody, null, 2));
}

async function getOfferDeepLink(issuerBase, path, credentialType) {
  if (!path) return undefined;
  const url = new URL(issuerBase + path);
  if (credentialType) url.searchParams.set("type", credentialType);
  const res = await fetch(url.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Fetch-offer error ${res.status}: ${JSON.stringify(err)}`);
  }
  const body = await res.json();
  return body.deepLink;
}

async function resolveOfferConfig(deepLink) {
  const url = new URL(deepLink.replace(/^haip:\/\//, "openid-credential-offer://"));
  if (url.protocol !== "openid-credential-offer:") {
    throw new Error("Unsupported offer scheme");
  }
  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  const res = await fetch(offerUri);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Offer-config error ${res.status}: ${JSON.stringify(err)}`);
  }
  return res.json();
}

async function promptTxCode(cfg) {
  // Non-interactive default: generate a dummy numeric code if required; issuer currently does not validate tx_code server-side.
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});


