/**
 * Auth proxy — OAuth 2.0 Authorization Code + PKCE flow for Claude.ai Connectors.
 *
 * Environment variables required:
 *   MCP_CLIENT_ID      — client ID entered in Claude.ai connector
 *   MCP_CLIENT_SECRET  — not used in PKCE flow but kept for validation
 *   PORT               — set automatically by Railway
 */

import http from "http";
import { spawn } from "child_process";
import { createHash, randomBytes } from "crypto";

const EXTERNAL_PORT = process.env.PORT || 3000;
const INTERNAL_PORT = 8091;
const CLIENT_ID = process.env.MCP_CLIENT_ID;
const CLIENT_SECRET = process.env.MCP_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing MCP_CLIENT_ID or MCP_CLIENT_SECRET env vars");
  process.exit(1);
}

// Static bearer token derived from credentials — no DB needed
const BEARER_TOKEN = createHash("sha256")
  .update(`${CLIENT_ID}:${CLIENT_SECRET}`)
  .digest("hex");

// In-memory store for auth codes (expire after 5 minutes)
const authCodes = new Map();

function generateCode() {
  return randomBytes(32).toString("hex");
}

function verifyPKCE(codeVerifier, codeChallenge, method) {
  if (method === "S256") {
    const hash = createHash("sha256").update(codeVerifier).digest("base64url");
    return hash === codeChallenge;
  }
  return codeVerifier === codeChallenge;
}

// Start supergateway on the internal port
const gw = spawn(
  "npx",
  ["-y", "supergateway", "--port", String(INTERNAL_PORT), "--stdio", "node index.js"],
  { stdio: "inherit", env: process.env }
);

gw.on("error", (err) => {
  console.error("Failed to start supergateway:", err);
  process.exit(1);
});

function proxyRequest(req, res) {
  const options = {
    hostname: "localhost",
    port: INTERNAL_PORT,
    path: req.url,
    method: req.method,
    headers: req.headers,
  };

  const proxy = http.request(options, (proxyRes) => {
    console.log(`[proxy] ${req.method} ${req.url} → ${proxyRes.statusCode}`);
    let body = "";
    proxyRes.on("data", (chunk) => (body += chunk));
    proxyRes.on("end", () => {
      if (proxyRes.statusCode >= 400 || body.includes("error")) {
        console.log(`[proxy] response body: ${body.slice(0, 500)}`);
      }
    });
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxy.on("error", (err) => {
    console.log(`[proxy] error: ${err.message}`);
    res.writeHead(502);
    res.end(JSON.stringify({ error: "Gateway error" }));
  });

  req.pipe(proxy);
}

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(json),
  });
  res.end(json);
}

setTimeout(() => {
  const server = http.createServer((req, res) => {
    const urlObj = new URL(req.url, `https://${req.headers.host}`);
    console.log(`[${req.method}] ${req.url}`);

    // RFC 9728 — protected resource metadata
    if (req.method === "GET" && urlObj.pathname === "/.well-known/oauth-protected-resource") {
      const base = `https://${req.headers.host}`;
      return send(res, 200, {
        resource: base,
        authorization_servers: [base],
      });
    }

    // RFC 8414 — authorization server metadata
    if (req.method === "GET" && (
      urlObj.pathname === "/.well-known/oauth-authorization-server" ||
      urlObj.pathname === "/.well-known/oauth-authorization-server/sse" ||
      urlObj.pathname === "/.well-known/oauth-authorization-server/mcp"
    )) {
      const base = `https://${req.headers.host}`;
      return send(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/oauth/token`,
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        response_types_supported: ["code"],
      });
    }

    // Authorization endpoint — auto-approve and redirect back to Claude.ai
    if (req.method === "GET" && urlObj.pathname === "/authorize") {
      const clientId = urlObj.searchParams.get("client_id");
      const redirectUri = urlObj.searchParams.get("redirect_uri");
      const state = urlObj.searchParams.get("state");
      const codeChallenge = urlObj.searchParams.get("code_challenge");
      const codeChallengeMethod = urlObj.searchParams.get("code_challenge_method") || "plain";

      console.log(`[authorize] client_id=${clientId} match=${clientId === CLIENT_ID}`);

      if (clientId !== CLIENT_ID) {
        return send(res, 401, { error: "unauthorized_client" });
      }

      const code = generateCode();
      authCodes.set(code, {
        codeChallenge,
        codeChallengeMethod,
        clientId,
        redirectUri,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const callback = new URL(redirectUri);
      callback.searchParams.set("code", code);
      if (state) callback.searchParams.set("state", state);

      console.log(`[authorize] redirecting to ${callback.toString().slice(0, 80)}...`);
      res.writeHead(302, { Location: callback.toString() });
      res.end();
      return;
    }

    // Token endpoint
    if (req.method === "POST" && urlObj.pathname === "/oauth/token") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        let params;
        try {
          if (req.headers["content-type"]?.includes("application/json")) {
            params = JSON.parse(body);
          } else {
            params = Object.fromEntries(new URLSearchParams(body));
          }
        } catch {
          return send(res, 400, { error: "invalid_request" });
        }

        const { grant_type, code, code_verifier } = params;
        console.log(`[token] grant_type=${grant_type}`);

        if (grant_type === "authorization_code") {
          const stored = authCodes.get(code);

          if (!stored || stored.expiresAt < Date.now()) {
            console.log(`[token] invalid or expired code`);
            return send(res, 400, { error: "invalid_grant" });
          }

          const pkceOk = verifyPKCE(code_verifier, stored.codeChallenge, stored.codeChallengeMethod);
          console.log(`[token] PKCE valid=${pkceOk}`);

          if (!pkceOk) {
            return send(res, 400, { error: "invalid_grant" });
          }

          authCodes.delete(code);

          return send(res, 200, {
            access_token: BEARER_TOKEN,
            token_type: "bearer",
            expires_in: 31536000,
          });
        }

        return send(res, 400, { error: "unsupported_grant_type" });
      });
      return;
    }

    // All other endpoints require a valid bearer token
    const auth = req.headers["authorization"];
    if (!auth || auth !== `Bearer ${BEARER_TOKEN}`) {
      console.log(`[auth] rejected — got: ${auth ?? "(none)"}`);
      return send(res, 401, { error: "unauthorized" });
    }

    proxyRequest(req, res);
  });

  server.listen(EXTERNAL_PORT, () => {
    console.log(`Auth proxy listening on port ${EXTERNAL_PORT}`);
  });
}, 3000);
