import { Router } from 'express';
import { ISSUER, RESOURCE_URI, SCOPES } from './config.ts';

/**
 * Discovery documents. A host follows exactly this chain: 401 names the
 * protected resource metadata, that names the authorization server, and that
 * names the endpoints.
 */
export const metadataRouter: Router = Router();

function protectedResourceMetadata() {
  return {
    resource: RESOURCE_URI,
    authorization_servers: [ISSUER],
    scopes_supported: SCOPES,
    bearer_methods_supported: ['header']
  };
}

// Both paths. RFC 9728 section 3.1: when the resource URL has a path
// component, clients try the path-suffixed form first, and a server that only
// answers the bare one is discovered by some hosts and not others.
metadataRouter.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json(protectedResourceMetadata());
});
metadataRouter.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  res.json(protectedResourceMetadata());
});

metadataRouter.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    revocation_endpoint: `${ISSUER}/revoke`,
    registration_endpoint: `${ISSUER}/register`,
    scopes_supported: SCOPES,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    // Both of these are required before Claude will choose CIMD over a
    // registration endpoint: its CIMD client authenticates as a public client,
    // so the token endpoint must accept PKCE-only requests with no secret.
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    // RFC 9207. Advertising this is what tells a client to reject an
    // authorization response that arrives without an iss.
    authorization_response_iss_parameter_supported: true,
    revocation_endpoint_auth_methods_supported: ['none']
  });
});

// Some clients look for the OpenID Connect document instead.
metadataRouter.get('/.well-known/openid-configuration', (_req, res) => {
  res.redirect(308, '/.well-known/oauth-authorization-server');
});
