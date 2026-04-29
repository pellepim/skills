---
name: WebSocket Security Patterns
description: Auth on upgrade, origin validation, message size, per-message authz, tenant isolation
applies_to:
  - feature: websocket
  - dependency: channels
  - dependency: websockets
  - dependency: python-socketio
  - dependency: starlette
version: 1
last_updated: 2026-04-29
---

# WebSocket Security Patterns

Optional module for the `/security` skill. Apply when the project uses WebSocket connections (Django Channels, FastAPI WebSocket, Socket.IO, raw websockets).

## 1. Authentication on Upgrade

**Red Flags:**
```python
# VULNERABLE - no auth check on WebSocket handshake
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()  # Anyone can connect
    data = await websocket.receive_json()

# SAFE - validate before accept
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    user = await authenticate_ws(websocket)
    if not user:
        await websocket.close(code=4401)
        return
    await websocket.accept()
```

**Checklist:**
- [ ] Authentication performed before `accept()` (during upgrade handshake)
- [ ] Token/session validated at connection time (cookie-based or token in query param / first message)
- [ ] If using cookies, SameSite and CSRF protections still apply
- [ ] If using token in URL (`?token=...`), token is short-lived and single-use (URLs appear in logs)

## 2. Origin Validation

**Red Flags:**
```python
# VULNERABLE - no origin check, any webpage can open a WebSocket
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()  # Cross-site WebSocket hijacking possible

# SAFE
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin not in ALLOWED_ORIGINS:
        await websocket.close(code=4403)
        return
    await websocket.accept()
```

**Checklist:**
- [ ] `Origin` header validated against allowlist before accepting connection
- [ ] Rejection for missing/invalid origin (not just logging)
- [ ] Origin check not bypassable via other headers

## 3. Message Size Limits

**Red Flags:**
```python
# VULNERABLE - no size limit on incoming messages
async def ws_handler(websocket):
    while True:
        data = await websocket.receive()  # 100MB message? Sure.
        process(data)
```

**Checklist:**
- [ ] Max message size configured at framework/server level (not just application)
- [ ] Binary messages have separate (typically larger) limits from text
- [ ] Fragmented message reassembly has a total size cap
- [ ] Large messages rejected before full read into memory

## 4. Rate Limiting

**Checklist:**
- [ ] Messages per second per connection limited (prevents flood)
- [ ] Connection rate per IP/user limited (prevents resource exhaustion)
- [ ] Maximum concurrent connections per user/IP enforced
- [ ] Slow clients (slow read/write) detected and disconnected (Slowloris-style)
- [ ] Rate limit violations logged with connection identity

## 5. Authorization Per Message

**Red Flags:**
```python
# VULNERABLE - auth checked once at connect, never again
async def ws_handler(websocket, user):
    while True:
        msg = await websocket.receive_json()
        if msg["action"] == "get_admin_data":
            await websocket.send_json(get_admin_data())  # User may not be admin

# SAFE - check per action
async def ws_handler(websocket, user):
    while True:
        msg = await websocket.receive_json()
        if msg["action"] == "get_admin_data":
            if not user.is_admin:
                await websocket.send_json({"error": "forbidden"})
                continue
            await websocket.send_json(get_admin_data())
```

**Checklist:**
- [ ] Authorization checked per message/action, not just at connection time
- [ ] User permissions re-validated periodically (user may be deactivated mid-session)
- [ ] Channel/room subscriptions verify access before joining
- [ ] Broadcast messages filtered by recipient authorization

## 6. Input Validation

**Checklist:**
- [ ] All incoming messages validated against expected schema (reject malformed)
- [ ] JSON parsing failures handled gracefully (no crash on invalid JSON)
- [ ] Action/event type validated against allowlist (no arbitrary handler dispatch)
- [ ] String fields in messages have length limits
- [ ] Binary data validated before processing (not blindly deserialized)

## 7. Connection Lifecycle

**Checklist:**
- [ ] Idle timeout enforced (disconnect inactive connections)
- [ ] Maximum connection duration cap (force reconnect periodically)
- [ ] Clean disconnect on server shutdown (close frames sent)
- [ ] Connection state cleaned up on abnormal disconnect (no resource leaks)
- [ ] Ping/pong health checks enabled (detect dead connections)

## 8. Cross-Tenant Isolation

**Checklist:**
- [ ] Messages from one tenant never broadcast to another tenant's connections
- [ ] Channel/room names incorporate tenant ID (no cross-tenant room join)
- [ ] Connection metadata includes tenant context for all downstream operations
- [ ] Shared pub/sub backends (Redis) use tenant-prefixed channels
