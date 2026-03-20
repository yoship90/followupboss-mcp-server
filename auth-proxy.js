/**
 * Auth proxy — sits in front of supergateway and enforces OAuth client credentials.
 *
 * Environment variables required:
 *   MCP_CLIENT_ID      — client ID Claude.ai will use
 *   MCP_CLIENT_SECRET  — client secret Claude.ai will use
 *   PORT               — set automatically by Railway
 *
 * OAuth token endpoint:  POST /oauth/token
 * MCP SSE endpoint:      GET  /sse  (proxied to supergateway on INTERNAL_PORT)
 * MCP message endpoint:  POST /message (proxied to supergateway on INTERNAL_PORT)
 */

import http from "http";
import { spawn } from "child_process";
import { createHash } from "crypto";

const EXTERNAL_PORT = process.env.PORT || 3000;
const INTERNAL_PORT = 8091;
const CLIENT_ID = process.env.MCP_CLIENT_ID;
const CLIENT_SECRET = process.env.MCP_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing MCP_CLIENT_ID or MCP_CLIENT_SECRET env vars");
  process.exit(1);
}

// Derive a static bearer token from the client credentials — no state needed
const BEARER_TOKEN = createHash("sha256")
  .update(`${CLIENT_ID}:${CLIENT_SECRET}`)
  .digest("hex");

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

// Wait for supergateway to be ready before accepting connections
const STARTUP_DELAY_MS = 3000;

function proxyRequest(req, res) {
  const options = {
    hostname: "localhost",
    port: INTERNAL_PORT,
    path: req.url,
    method: req.method,
    headers: req.headers,
  };

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxy.on("error", () => {
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
    console.log(`[${req.method}] ${req.url} — auth: ${req.headers["authorization"] ?? "(none)"}`);

    // OAuth 2.0 discovery endpoint — Claude.ai uses this to find the token URL
    if (req.method === "GET" && req.url === "/.well-known/oauth-authorization-server") {
      const host = req.headers.host;
      const base = `https://${host}`;
      return send(res, 200, {
        issuer: base,
        token_endpoint: `${base}/oauth/token`,
        grant_types_supported: ["client_credentials"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
    }

    // OAuth token endpoint — no auth required here
    if (req.method === "POST" && req.url === "/oauth/token") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        let params;
        try {
          // Support both JSON and application/x-www-form-urlencoded
          if (req.headers["content-type"]?.includes("application/json")) {
            params = JSON.parse(body);
          } else {
            params = Object.fromEntries(new URLSearchParams(body));
          }
        } catch {
          return send(res, 400, { error: "invalid_request" });
        }

        const { grant_type, client_id, client_secret } = params;

        console.log(`[token] grant_type=${grant_type} client_id=${client_id} match=${client_id === CLIENT_ID && client_secret === CLIENT_SECRET}`);

        if (grant_type !== "client_credentials") {
          return send(res, 400, { error: "unsupported_grant_type" });
        }

        if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) {
          return send(res, 401, { error: "invalid_client" });
        }

        return send(res, 200, {
          access_token: BEARER_TOKEN,
          token_type: "bearer",
          expires_in: 31536000, // 1 year — token is static so it never expires
        });
      });
      return;
    }

    // All other endpoints require a valid bearer token
    const auth = req.headers["authorization"];
    if (!auth || auth !== `Bearer ${BEARER_TOKEN}`) {
      return send(res, 401, { error: "unauthorized" });
    }

    proxyRequest(req, res);
  });

  server.listen(EXTERNAL_PORT, () => {
    console.log(`Auth proxy listening on port ${EXTERNAL_PORT}`);
    console.log(`OAuth token endpoint: POST /oauth/token`);
  });
}, STARTUP_DELAY_MS);
