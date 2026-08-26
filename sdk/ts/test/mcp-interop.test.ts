import { describe, expect, it } from "vitest";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  OAuthClientInformation,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { RsSdk, type Jwks } from "../src/index.js";
import { jwksOf, makeKey, signToken } from "./helpers.js";

const RESOURCE = "https://mcp.example.com/mcp/v1";
const RESOURCE_METADATA =
  "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/v1";
const ISSUER = "https://auth.example.com";
const REQUIRED_SCOPES = ["mcp:read", "mcp:write"] as const;

class CapturingProvider implements OAuthClientProvider {
  readonly redirectUrl = new URL("http://127.0.0.1/callback");
  readonly clientMetadata: OAuthClientMetadata = {
    client_name: "agent-auth interop fixture",
    redirect_uris: [this.redirectUrl.href],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
  readonly redirects: URL[] = [];
  private currentTokens: OAuthTokens | undefined;
  private clientInfo: OAuthClientInformation | undefined;
  private verifier = "";

  constructor(tokens?: OAuthTokens) {
    this.currentTokens = tokens;
  }

  clientInformation(): OAuthClientInformation | undefined {
    return this.clientInfo;
  }

  saveClientInformation(clientInformation: OAuthClientInformation): void {
    this.clientInfo = clientInformation;
  }

  tokens(): OAuthTokens | undefined {
    return this.currentTokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this.currentTokens = tokens;
  }

  redirectToAuthorization(authorizationUrl: URL): void {
    this.redirects.push(new URL(authorizationUrl));
  }

  saveCodeVerifier(codeVerifier: string): void {
    this.verifier = codeVerifier;
  }

  codeVerifier(): string {
    return this.verifier;
  }
}

function requestUrl(input: string | URL | Request): URL {
  if (input instanceof Request) return new URL(input.url);
  return new URL(input.toString());
}

describe("official MCP SDK 1.30 authorization interoperability", () => {
  it("c8_8_and_c8_8a_official_mcp_discovery_and_step_up", async () => {
    const key = await makeKey();
    const sdk = new RsSdk({
      resourceId: RESOURCE,
      issuer: ISSUER,
      jwksFetcher: async () => jwksOf(key) as Jwks,
    });
    sdk.seedJwks(jwksOf(key) as Jwks);

    const statuses: number[] = [];
    const challenges: string[] = [];
    const discoveryUrls: string[] = [];
    const registrationScopes: string[] = [];
    const fixtureFetch = async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = requestUrl(input);
      if (url.href === RESOURCE) {
        const authorization = new Headers(init?.headers).get("authorization");
        const result = await sdk.authenticate(authorization, {
          requireScopes: REQUIRED_SCOPES,
        });
        if (!result.ok) {
          statuses.push(result.status);
          challenges.push(result.headers["WWW-Authenticate"] ?? "");
          return new Response(null, {
            status: result.status,
            headers: result.headers,
          });
        }
        return new Response(null, { status: 202 });
      }

      discoveryUrls.push(url.href);
      if (url.href === RESOURCE_METADATA) {
        return Response.json({
          resource: RESOURCE,
          authorization_servers: [ISSUER],
        });
      }
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          registration_endpoint: `${ISSUER}/register`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      }
      if (url.href === `${ISSUER}/register`) {
        const registration = JSON.parse(String(init?.body)) as OAuthClientMetadata;
        registrationScopes.push(registration.scope ?? "");
        return Response.json(
          {
            ...registration,
            client_id: `interop-client-${registrationScopes.length}`,
          },
          { status: 201 },
        );
      }
      throw new Error(`unexpected interop request: ${url.href}`);
    };

    const message = {
      jsonrpc: "2.0" as const,
      id: 1,
      method: "tools/list",
      params: {},
    };

    const missingProvider = new CapturingProvider();
    const missingTransport = new StreamableHTTPClientTransport(
      new URL(RESOURCE),
      { authProvider: missingProvider, fetch: fixtureFetch },
    );
    await expect(missingTransport.send(message)).rejects.toThrow();
    expect(discoveryUrls).toContain(RESOURCE_METADATA);
    expect(registrationScopes[0]).toBe(REQUIRED_SCOPES.join(" "));
    expect(missingProvider.redirects).toHaveLength(1);
    expect(missingProvider.redirects[0]?.searchParams.get("scope")).toBe(
      REQUIRED_SCOPES.join(" "),
    );
    expect(challenges[0]).toContain(`resource_metadata="${RESOURCE_METADATA}"`);

    const readToken = await signToken({
      key,
      iss: ISSUER,
      aud: [RESOURCE],
      scope: "mcp:read",
    });
    const stepUpProvider = new CapturingProvider({
      access_token: readToken,
      token_type: "Bearer",
      scope: "mcp:read",
    });
    const stepUpTransport = new StreamableHTTPClientTransport(
      new URL(RESOURCE),
      { authProvider: stepUpProvider, fetch: fixtureFetch },
    );
    await expect(stepUpTransport.send(message)).rejects.toThrow();
    expect(statuses).toContain(403);
    expect(registrationScopes[1]).toBe(REQUIRED_SCOPES.join(" "));
    expect(stepUpProvider.redirects).toHaveLength(1);
    expect(stepUpProvider.redirects[0]?.searchParams.get("scope")).toBe(
      REQUIRED_SCOPES.join(" "),
    );
    expect(challenges.at(-1)).toBe(
      `Bearer error="insufficient_scope", scope="${REQUIRED_SCOPES.join(" ")}", resource_metadata="${RESOURCE_METADATA}"`,
    );

    const wrongAudienceToken = await signToken({
      key,
      iss: ISSUER,
      aud: ["https://other.example.com/mcp/v1"],
      scope: REQUIRED_SCOPES.join(" "),
    });
    const wrongAudience = await sdk.authenticate(
      `Bearer ${wrongAudienceToken}`,
      { requireScopes: REQUIRED_SCOPES },
    );
    expect(wrongAudience.ok).toBe(false);
    if (!wrongAudience.ok) {
      expect(wrongAudience.status).toBe(401);
      expect(wrongAudience.headers["WWW-Authenticate"]).toBe(
        `Bearer error="invalid_token", resource_metadata="${RESOURCE_METADATA}"`,
      );
    }
  });
});
