---
name: NestJS Security Patterns
description: Guards, pipes, ValidationPipe whitelist, interceptors, mass assignment via class-validator, RBAC
applies_to:
  - framework: nestjs
  - dependency: "@nestjs/core"
version: 1
last_updated: 2026-04-30
---

# NestJS Security Patterns

Apply when the project uses NestJS. Underlying platform is Express by default; Fastify variant
also common. The DI / decorator system shifts most footguns to "guard not applied" rather than
"input not validated" - assuming `ValidationPipe` is configured globally.

## 1. Global ValidationPipe

**Red Flags:**
```ts
// VULNERABLE - no global pipe; controllers without explicit @UsePipes accept arbitrary bodies
const app = await NestFactory.create(AppModule);
await app.listen(3000);

// SAFE
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,                                              // strips unknown properties (mass-assignment defense)
  forbidNonWhitelisted: true,                                   // reject bodies with extra keys (stricter)
  transform: true,                                              // type coercion based on DTO
  transformOptions: { enableImplicitConversion: false },        // explicit > implicit
  disableErrorMessages: process.env.NODE_ENV === "production",  // don't leak validator internals
}));
```

**Checklist:**
- [ ] `app.useGlobalPipes(new ValidationPipe(...))` invoked at startup, with `whitelist: true`
- [ ] `forbidNonWhitelisted: true` for stricter contracts (rejects extra keys instead of silently dropping)
- [ ] DTOs use `class-validator` decorators (`@IsString()`, `@MaxLength`, `@IsEmail`, `@Length`) - not just type
      annotations (TS types are erased at runtime)
- [ ] Sensitive fields (`isAdmin`, `role`, `tenantId`) NOT in input DTOs; defined only on entity / response DTO

## 2. Guards (AuthN / AuthZ)

**Red Flags:**
```ts
// VULNERABLE - guard decorator missing on a sensitive controller
@Controller("admin")
export class AdminController {
  @Get("users") listUsers() { /* ... */ }                       // public unless guard applied at class or method level
}

// VULNERABLE - guard registered but not used
providers: [AuthGuard]                                          // declared but never @UseGuards(AuthGuard)
```

**Checklist:**
- [ ] Auth guard applied globally (`app.useGlobalGuards(...)`) OR explicitly per controller / route via `@UseGuards`
- [ ] Public routes opt-out via `@Public()` decorator + reflector check; the default is "auth required"
- [ ] Role/permission guard layered on top of auth (`@UseGuards(AuthGuard, RolesGuard)`), not an `if (user.isAdmin)`
      inside the handler
- [ ] Custom decorators (`@Roles`, `@RequirePermission`) read by guard via `Reflector` - confirm guard is actually
      registered if decorator is used
- [ ] WebSocket gateways and microservice handlers re-apply guards (HTTP guards do NOT auto-apply)

## 3. Mass Assignment

**Red Flags:**
```ts
// VULNERABLE - DTO mirrors entity, includes role/isAdmin
class UpdateUserDto {
  @IsString() name?: string;
  @IsString() role?: string;                                    // attacker can set
}

// VULNERABLE - skipping ValidationPipe and passing raw body
@Post() create(@Req() req) { return this.svc.create(req.body); }
```

**Checklist:**
- [ ] Input DTOs define ONLY client-settable fields; never include `role`, `isAdmin`, `tenantId`, `userId`,
      `passwordHash`, `emailVerified`
- [ ] Output / response DTOs separate from entity (use `@Exclude` / `@Expose` from `class-transformer` plus
      `ClassSerializerInterceptor`) - prevents leaking `passwordHash` etc.
- [ ] `@UseInterceptors(ClassSerializerInterceptor)` applied globally so `@Exclude` is honored

## 4. Helmet / CORS

**Checklist:**
- [ ] `app.use(helmet())` (or `@fastify/helmet` for Fastify adapter) registered
- [ ] `app.enableCors({ origin: ['https://...'], credentials: true })` with explicit allowlist; never `origin: '*'` with
      credentials
- [ ] `app.disable("x-powered-by")` (Express) / Fastify defaults to no banner

## 5. JWT / Passport Strategies

**Red Flags:**
```ts
// VULNERABLE - no algorithms specified; accepts none
JwtModule.register({ secret: "..." });

// VULNERABLE - JwtStrategy passes ignoreExpiration: true
super({ secretOrKey, ignoreExpiration: true, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() });
```

**Checklist:**
- [ ] `JwtModule.register({ signOptions: { algorithm: 'RS256', expiresIn }, verifyOptions: { algorithms: ['RS256'],
      audience, issuer } })`
- [ ] Strategies do NOT set `ignoreExpiration: true`
- [ ] `secretOrKeyProvider` for key rotation / JWKS fetched over HTTPS to a pinned host
- [ ] See SKILL.md "JWT" + `modules/custom-jwt.md`

## 6. Rate Limiting & Throttling

**Checklist:**
- [ ] `@nestjs/throttler` registered globally; tighter throttle on auth endpoints (`@Throttle({ default: { ttl, limit }})`)
- [ ] Per-account / per-user throttle key when authenticated; IP-based pre-auth (with `trust proxy` configured)

## 7. File Uploads

**Checklist:**
- [ ] `FileInterceptor` / `FilesInterceptor` configured with `limits: { fileSize, files }`
- [ ] MIME type validated via `fileFilter` *and* magic-byte check (don't trust `mimetype` from client)
- [ ] See `modules/file-upload.md` for full coverage

## 8. Microservices / WebSockets

**Checklist:**
- [ ] WebSocket gateway: `WsAuthGuard` on every message handler (not just `@SubscribeMessage` global)
- [ ] Microservice transport (TCP/Redis/NATS): authentication on each message; do not assume the broker is private
- [ ] Subscribe-time auth different from message-time auth (a connection authenticated as user A should not relay user
      B's messages)

## 9. Health & Metrics Endpoints

**Checklist:**
- [ ] `@nestjs/terminus` health endpoint does not leak internal hostnames/versions in responses
- [ ] Metrics endpoint (`prom-client`, `nestjs-prometheus`) auth-gated or bound to internal-only port
- [ ] `/api-docs` (Swagger) auth-gated or disabled in production

## References

- NestJS security: https://docs.nestjs.com/security
- class-validator: https://github.com/typestack/class-validator
