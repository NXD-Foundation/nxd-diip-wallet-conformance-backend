/**
 * Route Utilities - VCI v1.0 and VP v1.0 compliant
 * Ported from rfc-issuer-v1 with adaptations for diip-v4
 */

import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "./cryptoUtils.js";
import { getSDsFromPresentationDef } from "./vpHeplers.js";
import { storeVPSession, getVPSession } from "../services/cacheServiceRedis.js";
import { createPublicKey } from "crypto";
import base64url from "base64url";
import jwt from "jsonwebtoken";

// ============================================================================
// SHARED CONSTANTS
// ============================================================================

export const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
export const PROXY_PATH = process.env.PROXY_PATH || null;

export const DEFAULT_CREDENTIAL_TYPE = "VerifiablePortableDocumentA2SDJWT";
export const DEFAULT_SIGNATURE_TYPE = "jwt";
export const DEFAULT_CLIENT_ID_SCHEME = "redirect_uri";

export const QR_CONFIG = {
  type: "png",
  ec_level: "H",
  size: 10,
  margin: 10,
};

export const CLIENT_METADATA = {
  client_name: "NXD  DIIP Verifier",
  logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
  location: "Greece",
  cover_uri: "string",
  description: "EWC pilot case verification",
  // VP v1.0: Use vp_formats_supported
  vp_formats_supported: {
    "dc+sd-jwt": {
      "sd-jwt_alg_values": ["ES256", "ES384"],
      "kb-jwt_alg_values": ["ES256", "ES384"],
    },
    "vc+sd-jwt": {
      "sd-jwt_alg_values": ["ES256", "ES384"],
      "kb-jwt_alg_values": ["ES256", "ES384"],
    },
    jwt_vc_json: {
      alg_values: ["ES256", "ES384"],
    },
  },
};

export const TX_CODE_CONFIG = {
  length: 4,
  input_mode: "numeric",
  description: "Please provide the one-time code that was sent via e-mail or offline",
};

export const URL_SCHEMES = {
  STANDARD: "openid-credential-offer://",
  HAIP: "haip://",
  OPENID4VP: "openid4vp://",
};

export const ERROR_MESSAGES = {
  SESSION_CREATION_FAILED: "Failed to create session",
  QR_GENERATION_FAILED: "Failed to generate QR code",
  INVALID_SESSION_ID: "Invalid session ID",
  INVALID_CREDENTIAL_TYPE: "Invalid credential type",
  STORAGE_ERROR: "Storage operation failed",
  QR_ENCODING_ERROR: "QR code encoding failed",
  CRYPTO_KEY_LOAD_ERROR: "Failed to load cryptographic keys",
  ITB_SESSION_EXPIRED: "ITB session expired",
  INVALID_RESPONSE_TYPE: "Invalid response_type",
  NO_CREDENTIALS_REQUESTED: "no credentials requested",
  PARSE_AUTHORIZATION_DETAILS_ERROR: "error parsing authorization details",
  MISSING_RESPONSE_TYPE: "authorizationDetails missing response_type",
  MISSING_CODE_CHALLENGE: "authorizationDetails missing code_challenge",
  PAR_REQUEST_NOT_FOUND: "ERROR: request_uri present in authorization endpoint, but no par request cached for request_uri",
  ISSUANCE_SESSION_NOT_FOUND: "issuance session not found",
  NO_JWT_PRESENTED: "no jwt presented",
};

// Default DCQL query configuration (VP v1.0)
export const DEFAULT_DCQL_QUERY = {
  credentials: [
    {
      id: "cmwallet",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["urn:eu.europa.ec.eudi:pid:1"],
      },
      claims: [
        { path: ["family_name"] },
      ],
    },
  ],
};

// Default transaction data configuration
export const DEFAULT_TRANSACTION_DATA = {
  type: "qes_authorization",
  transaction_data_hashes_alg: ["sha-256"],
  purpose: "Verification of identity",
  documentDigests: [
    {
      hash: "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
      label: "Example Contract",
      hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
      documentLocations: [
        {
          uri: "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
          method: {
            type: "public",
          },
        },
      ],
      dtbsr: "VYDl4oTeJ5TmIPCXKdTX1MSWRLI9CKYcyMRz6xlaGg",
    },
  ],
};

export const CONFIG = {
  SERVER_URL: process.env.SERVER_URL || "http://localhost:3000",
  get CLIENT_ID() {
    const hostname = new URL(this.SERVER_URL).hostname;
    return `x509_san_dns:${hostname}`;
  },
  DEFAULT_RESPONSE_MODE: "direct_post",
  DEFAULT_JAR_ALG: "ES256",
  DEFAULT_NONCE_LENGTH: 16,
  QR_CONFIG: {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  },
  MEDIA_TYPE: "PNG",
  CONTENT_TYPE: "application/oauth-authz-req+jwt",
  SESSION_STATUS: {
    PENDING: "pending",
  },
  ERROR_MESSAGES: {
    INVALID_SESSION: "Invalid session ID",
    FILE_READ_ERROR: "Failed to read configuration file",
    QR_GENERATION_ERROR: "Failed to generate QR code",
    SESSION_STORE_ERROR: "Failed to store session",
    JWT_BUILD_ERROR: "Failed to build JWT",
    JWK_GENERATION_ERROR: "Failed to generate JWK",
  },
};

// ============================================================================
// LOGGING UTILITIES
// ============================================================================

export const logUtilityError = (context, error = {}, metadata = {}) => {
  const payload = {
    message: error?.message || "Unknown error",
    stack: error?.stack,
    ...metadata,
  };
  console.error(`[${context}]`, payload);
};

// ============================================================================
// QR CODE AND URL GENERATION UTILITIES
// ============================================================================

export const generateQRCode = async (credentialOffer, sessionId = null) => {
  try {
    if (sessionId) {
      console.log(`[QR] Generating QR code for session ${sessionId}`);
    }
    
    const code = qr.image(credentialOffer, QR_CONFIG);
    const mediaType = "PNG";
    const encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
    
    return encodedQR;
  } catch (error) {
    logUtilityError("generateQRCode", error);
    throw new Error(ERROR_MESSAGES.QR_GENERATION_FAILED);
  }
};

// ============================================================================
// VP REQUEST GENERATION UTILITIES
// ============================================================================

/**
 * Generate VP request with common parameters
 * @param {Object} params - Parameters for VP request generation
 * @returns {Promise<Object>} - The VP request result
 */
export async function generateVPRequest(params) {
  const {
    sessionId,
    responseMode,
    jarAlg,
    presentationDefinition,
    clientId,
    clientMetadata,
    kid,
    serverURL,
    dcqlQuery = null,
    transactionData = null,
    usePostMethod = false,
    routePath,
  } = params;

  console.log(`[VP] Starting VP request generation for session ${sessionId}`);

  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const responseUri = `${serverURL}/direct_post/${sessionId}`;

  // Prepare session data
  const sessionData = {
    nonce,
    response_mode: responseMode,
    state,
    jar_alg: jarAlg || CONFIG.DEFAULT_JAR_ALG,
    client_id: clientId,
  };

  if (presentationDefinition) {
    sessionData.presentation_definition = presentationDefinition;
    sessionData.sdsRequested = getSDsFromPresentationDef(presentationDefinition);
  }

  if (dcqlQuery) {
    sessionData.dcql_query = dcqlQuery;
  }

  if (transactionData) {
    sessionData.transaction_data = [transactionData];
  }

  // Store session data
  await storeVPSessionData(sessionId, sessionData);

  // Build VP request JWT
  await buildVpRequestJWT(
    clientId,
    responseUri,
    null, // privateKey - determined from client_id scheme
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcqlQuery,
    transactionData ? [transactionData] : null,
    responseMode
  );

  // Create OpenID4VP request URL
  const requestUri = `${serverURL}${routePath}/${sessionId}`;
  const vpRequest = createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod);

  // Generate QR code
  const qrCode = await generateQRCode(vpRequest, sessionId);

  const response = createVPRequestResponse(qrCode, vpRequest, sessionId);
  console.log(`[VP] VP request generation completed for session ${sessionId}`);
  
  return response;
}

/**
 * Helper function to process VP Request
 * @param {Object} params - Parameters for VP request processing
 * @returns {Promise<Object>} - The result object with JWT or error
 */
export async function processVPRequest(params) {
  const {
    sessionId,
    clientMetadata,
    serverURL,
    clientId,
    kid,
    audience,
    walletNonce,
    walletMetadata,
  } = params;

  console.log(`[VP] Processing VP request for session ${sessionId}`);

  try {
    const vpSession = await getVPSession(sessionId);

    if (!vpSession) {
      console.error(`[VP] VP session not found: ${sessionId}`);
      return { error: CONFIG.ERROR_MESSAGES.INVALID_SESSION, status: 400 };
    }

    const responseUri = `${serverURL}/direct_post/${sessionId}`;

    const vpRequestJWT = await buildVpRequestJWT(
      clientId,
      responseUri,
      null, // privateKey
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      audience,
      walletNonce,
      walletMetadata
    );

    console.log(`[VP] VP request JWT built successfully for session ${sessionId}`);
    return { jwt: vpRequestJWT, status: 200 };
  } catch (error) {
    logUtilityError("processVPRequest", error);
    throw new Error(CONFIG.ERROR_MESSAGES.JWT_BUILD_ERROR);
  }
}

/**
 * Create transaction data object with credential IDs
 * @param {Object} presentationDefinitionOrDcqlQuery - The presentation definition or DCQL query
 * @returns {Object} - The transaction data object
 */
export function createTransactionData(presentationDefinitionOrDcqlQuery) {
  let credentialIds = [];
  
  // Handle Presentation Definition (PEX)
  if (presentationDefinitionOrDcqlQuery?.input_descriptors) {
    credentialIds = presentationDefinitionOrDcqlQuery.input_descriptors.map(
      (descriptor) => descriptor.id
    );
  }
  // Handle DCQL Query
  else if (presentationDefinitionOrDcqlQuery?.credentials) {
    credentialIds = presentationDefinitionOrDcqlQuery.credentials.map(
      (credential) => credential.id
    );
  }
  
  return {
    ...DEFAULT_TRANSACTION_DATA,
    credential_ids: credentialIds,
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4(),
  };
}

/**
 * Create an OpenID4VP request URL (VP v1.0)
 * @param {string} requestUri - The request URI
 * @param {string} clientId - The client ID
 * @param {boolean} usePostMethod - Whether to use POST method
 * @returns {string} - The OpenID4VP request URL
 */
export function createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod = false) {
  const baseUrl = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  // VP v1.0: Support request_uri_method parameter
  return usePostMethod ? `${baseUrl}&request_uri_method=post` : baseUrl;
}

/**
 * Store VP session data
 * @param {string} sessionId - The session ID
 * @param {Object} sessionData - The session data to store
 * @returns {Promise<void>}
 */
export async function storeVPSessionData(sessionId, sessionData) {
  try {
    await storeVPSession(sessionId, {
      uuid: sessionId,
      status: CONFIG.SESSION_STATUS.PENDING,
      claims: null,
      ...sessionData,
    });
  } catch (error) {
    logUtilityError("storeVPSessionData", error);
    throw new Error(CONFIG.ERROR_MESSAGES.SESSION_STORE_ERROR);
  }
}

/**
 * Create a standard VP request response
 * @param {string} qrCode - The QR code data URI
 * @param {string} deepLink - The deep link URL
 * @param {string} sessionId - The session ID
 * @returns {Object} - The response object
 */
export function createVPRequestResponse(qrCode, deepLink, sessionId) {
  return {
    qr: qrCode,
    deepLink,
    sessionId,
  };
}

// ============================================================================
// DID UTILITIES
// ============================================================================

/**
 * Generate DID JWK identifier from private key
 * @param {string} privateKey - The private key in PEM format
 * @returns {string} - The DID JWK identifier
 */
export function generateDidJwkIdentifier(privateKey) {
  try {
    const publicKey = createPublicKey(privateKey);
    const jwk = publicKey.export({ format: 'jwk' });
    return `did:jwk:${base64url(JSON.stringify(jwk))}`;
  } catch (error) {
    logUtilityError("generateDidJwkIdentifier", error);
    throw new Error(CONFIG.ERROR_MESSAGES.JWK_GENERATION_ERROR);
  }
}

/**
 * Create DID controller from server URL (VP v1.0)
 * @param {string} serverURL - The server URL
 * @returns {string} - The DID controller
 */
export function createDidController(serverURL) {
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  return controller;
}

/**
 * Generate DID-based client ID and key ID (VP v1.0)
 * @param {string} serverURL - The server URL
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidIdentifiers(serverURL) {
  const controller = createDidController(serverURL);
  // VP v1.0: Use decentralized_identifier prefix
  const client_id = `decentralized_identifier:did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;
  return { client_id, kid };
}

/**
 * Generate DID JWK identifiers (VP v1.0)
 * @param {string} didJwkIdentifier - The DID JWK identifier
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidJwkIdentifiers(didJwkIdentifier) {
  // VP v1.0: Use decentralized_identifier prefix
  const client_id = `decentralized_identifier:${didJwkIdentifier}`;
  const kid = `${didJwkIdentifier}#0`;
  return { client_id, kid };
}

// ============================================================================
// WIA AND WUA VALIDATION UTILITIES (VCI v1.0)
// ============================================================================

/**
 * Validates Wallet Instance Attestation (WIA) JWT
 * Per EUDI TS3 Wallet Unit Attestation spec
 * 
 * @param {string} wiaJwt - The WIA JWT string
 * @param {string} sessionId - Session ID for logging
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>}
 */
export const validateWIA = async (wiaJwt, sessionId = null) => {
  try {
    if (!wiaJwt || typeof wiaJwt !== 'string') {
      return { valid: false, error: 'WIA JWT is missing or invalid' };
    }

    // Decode JWT to check structure
    const decoded = jwt.decode(wiaJwt, { complete: true });
    if (!decoded || !decoded.header || !decoded.payload) {
      return { valid: false, error: 'WIA JWT is malformed' };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decoded.payload.exp && decoded.payload.exp < now) {
      return { valid: false, error: 'WIA JWT has expired' };
    }

    // Check required claims
    if (!decoded.payload.iss) {
      return { valid: false, error: 'WIA JWT missing iss claim' };
    }

    // Per spec: WIA SHALL have a time-to-live of less than 24 hours
    if (decoded.payload.exp && decoded.payload.iat) {
      const ttlInSeconds = decoded.payload.exp - decoded.payload.iat;
      const ttlInHours = ttlInSeconds / 3600;
      const maxTtlHours = 24;
      
      if (ttlInSeconds < 0) {
        return { valid: false, error: 'WIA JWT has invalid expiration (exp < iat)' };
      }
      
      if (ttlInHours >= maxTtlHours) {
        return { valid: false, error: `WIA JWT TTL (${ttlInHours.toFixed(2)} hours) exceeds maximum allowed (${maxTtlHours} hours)` };
      }
    } else if (!decoded.payload.exp || !decoded.payload.iat) {
      return { valid: false, error: 'WIA JWT missing exp or iat claim required for TTL validation' };
    }

    if (sessionId) {
      const ttlInHours = decoded.payload.exp && decoded.payload.iat 
        ? ((decoded.payload.exp - decoded.payload.iat) / 3600).toFixed(2)
        : 'unknown';
      console.log(`[WIA] Validation passed for session ${sessionId}, TTL: ${ttlInHours} hours`);
    }

    return { valid: true, payload: decoded.payload };
  } catch (error) {
    const errorMsg = `WIA validation error: ${error.message}`;
    console.error(`[WIA] ${errorMsg}`);
    return { valid: false, error: errorMsg };
  }
};

/**
 * Validates Wallet Unit Attestation (WUA) JWT
 * Per EUDI TS3 Wallet Unit Attestation spec
 * 
 * @param {string} wuaJwt - The WUA JWT string
 * @param {string} sessionId - Session ID for logging
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>}
 */
export const validateWUA = async (wuaJwt, sessionId = null) => {
  try {
    if (!wuaJwt || typeof wuaJwt !== 'string') {
      return { valid: false, error: 'WUA JWT is missing or invalid' };
    }

    // Decode JWT to check structure
    const decoded = jwt.decode(wuaJwt, { complete: true });
    if (!decoded || !decoded.header || !decoded.payload) {
      return { valid: false, error: 'WUA JWT is malformed' };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decoded.payload.exp && decoded.payload.exp < now) {
      return { valid: false, error: 'WUA JWT has expired' };
    }

    // Check required claims
    if (!decoded.payload.iss) {
      return { valid: false, error: 'WUA JWT missing iss claim' };
    }

    // Check for eudi_wallet_info (optional but recommended)
    const hasEudiWalletInfo = !!decoded.payload.eudi_wallet_info;
    if (!hasEudiWalletInfo) {
      return { valid: false, error: 'eudi_wallet_info claim is missing' };
    }

    const generalInfo = decoded.payload.eudi_wallet_info.general_info;
    const keyStorageInfo = decoded.payload.eudi_wallet_info.key_storage_info;
    if (!generalInfo || !keyStorageInfo) {
      return { valid: false, error: 'general_info or key_storage_info claim is missing' };
    }
    
    // Check for attested_keys (required per spec)
    const hasAttestedKeys = Array.isArray(decoded.payload.attested_keys) && decoded.payload.attested_keys.length > 0;
    
    // Check for status/revocation information (required per spec)
    const hasStatus = !!decoded.payload.status && !!decoded.payload.status.status_list;

    if (sessionId) {
      console.log(`[WUA] Validation passed for session ${sessionId}`, {
        hasEudiWalletInfo,
        hasAttestedKeys,
        hasStatus,
        attestedKeysCount: decoded.payload.attested_keys?.length || 0
      });
    }

    // Warn if required elements are missing
    if (!hasAttestedKeys) {
      console.warn(`[WUA] Missing attested_keys for session ${sessionId}`);
    }
    if (!hasStatus) {
      console.warn(`[WUA] Missing status/revocation information for session ${sessionId}`);
    }

    return { valid: true, payload: decoded.payload };
  } catch (error) {
    const errorMsg = `WUA validation error: ${error.message}`;
    console.error(`[WUA] ${errorMsg}`);
    return { valid: false, error: errorMsg };
  }
};

/**
 * Extracts WIA from token endpoint request
 * Per spec: WIA SHALL be sent as client_assertion with client_assertion_type
 * 
 * @param {object} reqBody - Request body
 * @returns {string|null} - WIA JWT or null if not found
 */
export const extractWIAFromTokenRequest = (reqBody) => {
  if (reqBody.client_assertion && reqBody.client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return reqBody.client_assertion;
  }
  return null;
};

/**
 * Extracts WUA from credential request
 * WUA can be in proofs.attestation or in the header of proofs.jwt
 * 
 * @param {object} requestBody - Credential request body
 * @returns {string|null} - WUA JWT or null if not found
 */
export const extractWUAFromCredentialRequest = (requestBody) => {
  // Check for key_attestation in proofs.attestation
  if (requestBody.proofs && requestBody.proofs.attestation) {
    const attestation = requestBody.proofs.attestation;
    if (typeof attestation === 'string') {
      return attestation;
    } else if (attestation && typeof attestation === 'object' && attestation.jwt) {
      return attestation.jwt;
    }
  }
  
  // Check for key_attestation in proofs.jwt header
  if (requestBody.proofs && requestBody.proofs.jwt) {
    const jwtProof = Array.isArray(requestBody.proofs.jwt) 
      ? requestBody.proofs.jwt[0] 
      : requestBody.proofs.jwt;
    
    if (typeof jwtProof === 'string') {
      try {
        const decoded = jwt.decode(jwtProof, { complete: true });
        if (decoded && decoded.header && decoded.header.key_attestation) {
          return decoded.header.key_attestation;
        }
      } catch (e) {
        // Not a valid JWT, ignore
      }
    }
  }
  
  return null;
};

// ============================================================================
// ERROR HANDLING UTILITIES
// ============================================================================

export const createErrorResponse = (error, description, status = 500) => {
  return {
    status,
    body: {
      error: error || "server_error",
      error_description: description || "An unexpected error occurred"
    }
  };
};

export const handleRouteError = (error, context, res) => {
  logUtilityError(`${context} error`, error);
  const errorResponse = createErrorResponse("server_error", error.message, 500);
  res.status(errorResponse.status).json(errorResponse.body);
};

export const sendSuccessResponse = (res, data, status = 200) => {
  res.status(status).json(data);
};

export const sendErrorResponse = (res, error, description, status = 500) => {
  const errorResponse = createErrorResponse(error, description, status);
  res.status(errorResponse.status).json(errorResponse.body);
};
