---
name: WebSocket Security Patterns
description: Upgrade auth, origin check, message size, per-message authz, tenant isolation, socket.io adapter
applies_to:
  - feature: websocket
  - dependency: ws
  - dependency: socket.io
  - dependency: "@fastify/websocket"
  - dependency: uWebSockets.js
version: 1
last_updated: 2026-04-30
---

# WebSocket Security Patterns

Apply when the project uses WebSockets (raw `ws`, `socket.io`, or framework integrations).

## 1. Origin Check on Upgrade

**Red Flags:**
```js
// VULNERABLE - no origin check; cross-site WebSocket hijacking with cookie auth
const wss = new WebSocketServer({ server });

// VULNERABLE - permissive origin
io.engine.opts.allowRequest = (req, cb) => cb(null, true);
```

**Checklist:**
- [ ] `verifyClient` (`ws`) or `allowRequest` (`socket.io`) checks `Origin` header against allowlist
- [ ] Cookie-based auth on WebSocket REQUIRES origin check - browsers send cookies on cross-origin upgrade
- [ ] socket.io: configure `cors: { origin: [...] }` with explicit allowlist; not `'*'` with credentials

## 2. Authentication on Connection

**Red Flags:**
```js
// VULNERABLE - assume cookie is enough; no token verification on upgrade
wss.on("connection", (ws, req) => {
  // accepts any client; auth check deferred to message handler (already too late for some message types)
});

// VULNERABLE - token in URL query (logged by proxies, leaks via referrer)
new WebSocket(`wss://api/?token=${jwt}`);
```

**Checklist:**
- [ ] Upgrade request authenticated: cookie OR `Authorization` header OR a short-lived ticket fetched over HTTPS
- [ ] Tokens NOT in URL (use `Sec-WebSocket-Protocol` header to carry a JWT, or pre-issue a single-use ticket)
- [ ] Authentication failure → `socket.destroy()` BEFORE the upgrade completes (prevents resource consumption)

## 3. Per-Message Authorization

**Red Flags:**
```js
// VULNERABLE - subscribe accepts any channel; user A subscribes to user B's private channel
socket.on("subscribe", (channel) => socket.join(channel));

// VULNERABLE - publish broadcasts globally without authz
socket.on("publish", (channel, msg) => io.to(channel).emit("msg", msg));
```

**Checklist:**
- [ ] Channel/room subscribe handlers authorize based on `socket.user`: tenant scope, ownership, role
- [ ] Publish handlers verify the user is permitted to write to the channel
- [ ] Channel names contain tenant identifiers; impossible to subscribe to other tenants by guessing IDs
- [ ] Server filters outbound events; do not rely on the client to drop events meant for other users

## 4. Message Size & Rate Limits

**Red Flags:**
```js
// VULNERABLE - no maxPayload; attacker sends 1 GB frame
new WebSocketServer({ server });

// VULNERABLE - no per-connection rate limit; flooded messages stall event loop
```

**Checklist:**
- [ ] `maxPayload` (ws) or `maxHttpBufferSize` (socket.io) set to bound per-message size (1-100 KB typical)
- [ ] Per-connection rate limit (token bucket) on inbound messages
- [ ] Per-IP / per-user connection limit (max concurrent connections)
- [ ] Idle timeout: drop connections that send no traffic for N minutes

## 5. Pong / Ping Heartbeat

**Checklist:**
- [ ] Server pings periodically; drops clients that don't pong (avoids dead-connection accumulation)
- [ ] Client-driven ping flooding rate-limited (otherwise an attacker can keep many connections alive cheaply)

## 6. Adapter / Pub-Sub (socket.io)

**Checklist:**
- [ ] Redis adapter / cluster: do not assume the broker is private; messages may be observable to anyone with broker
      access. Avoid putting sensitive payloads in events; reference IDs and have the receiver fetch via authenticated
      RPC if needed
- [ ] Adapter authentication / TLS in place (Redis ACL, TLS-enabled)

## 7. CSRF on Upgrade

**Checklist:**
- [ ] Upgrade requests verified via Origin (see #1)
- [ ] Token-only auth (no cookies) avoids CSRF entirely on WebSocket
- [ ] If cookies + token are both used, the token must be in a header (impossible to set in cross-origin WebSocket
      from a browser) - this is a viable defense

## 8. Disconnection / Cleanup

**Checklist:**
- [ ] On disconnect, server-side state per-connection (subscriptions, pending writes) cleaned up
- [ ] No memory leak from accumulating closures referencing the socket

## References

- WebSocket security (OWASP): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- ws library: https://github.com/websockets/ws
- socket.io security: https://socket.io/docs/v4/security/
