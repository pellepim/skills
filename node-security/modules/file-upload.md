---
name: File Upload Security Patterns
description: multer/busboy limits, MIME spoofing, magic byte check, path traversal, image processing exploits, safe serving
applies_to:
  - feature: file-upload
  - dependency: multer
  - dependency: busboy
  - dependency: "@fastify/multipart"
  - dependency: sharp
  - dependency: jimp
  - dependency: formidable
version: 1
last_updated: 2026-04-30
---

# File Upload Security Patterns

Apply when the project accepts user file uploads. Covers parsing, validation, processing, storage,
and serving.

## 1. Parser Limits

**Red Flags:**
```js
// VULNERABLE - multer default has no fileSize limit
const upload = multer({ dest: "uploads/" });

// VULNERABLE - busboy without limits
const bb = busboy({ headers: req.headers });

// SAFE
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024, files: 5, fields: 20, fieldSize: 1 * 1024 * 1024 },
});

const bb = busboy({
  headers: req.headers,
  limits: { fileSize: 10_000_000, files: 5, fields: 20, fieldSize: 1_000_000 },
});
```

**Checklist:**
- [ ] `limits.fileSize` set explicitly (no default in multer)
- [ ] `limits.files` set (cap concurrent uploaded files per request)
- [ ] `limits.fields` and `limits.fieldSize` set for non-file form fields
- [ ] On `'limit'` event / `LIMIT_FILE_SIZE` error: reject and clean up partial files
- [ ] Upstream proxy (`client_max_body_size` nginx, etc.) also caps total body size as defense in depth

## 2. MIME / Type Validation

**Red Flags:**
```js
// VULNERABLE - trusting client-supplied MIME
if (file.mimetype === "image/png") { /* accept */ }             // attacker sets Content-Type: image/png on a .exe

// VULNERABLE - extension-based check
if (path.extname(file.originalname) === ".png") { /* ... */ }
```

**Checklist:**
- [ ] MIME type detected from magic bytes (`file-type`, `magic-bytes.js`) - not from client `Content-Type` or filename
      extension
- [ ] Allowlist of accepted types (e.g. `["image/png", "image/jpeg", "image/webp"]`); reject everything else
- [ ] For images: dimensions read via image library (sharp/jimp `metadata()`) and bounded BEFORE full decode
- [ ] SVG uploads sanitized with DOMPurify (SVG profile) or rasterized to PNG before serving (SVG is XML and can carry
      `<script>`)

## 3. Filename Handling

**Red Flags:**
```js
// VULNERABLE - using user-supplied name on disk
fs.writeFileSync(path.join("uploads", file.originalname), buf); // ../../etc/passwd

// VULNERABLE - using user-supplied name in Content-Disposition
res.setHeader("Content-Disposition", `attachment; filename="${file.originalname}"`);
// quote-injection / RFC 5987 encoding bypass for IE/old browsers
```

**Checklist:**
- [ ] Generated filename on disk (UUID + validated extension); never use `file.originalname` as the disk path
- [ ] Path computed via `path.join(BASE, generatedName)` then `path.resolve` boundary-checked against BASE
- [ ] `Content-Disposition` filename uses RFC 5987 encoding (`filename*=UTF-8''<encoded>`); no raw user input in
      attribute value
- [ ] Reject filenames containing `..`, `/`, `\`, null bytes (`\0`), Windows drive prefixes

## 4. Image Processing Exploits

**Red Flags:**
```js
// VULNERABLE - sharp without limitInputPixels
await sharp(buf).resize(800, 600).toBuffer();                   // pixel-bomb decodes to GB

// VULNERABLE - GraphicsMagick / ImageMagick `gm` shells out to convert (CVE-2016-3714 ImageTragick if version old)
gm(buf).resize(800).toBuffer();
```

**Checklist:**
- [ ] `sharp({ limitInputPixels: 50_000_000 })` or per-call equivalent - prevents pixel-bomb decode
- [ ] Image dimensions read first (`sharp(buf).metadata()`); reject extreme dimensions before full decode
- [ ] ImageMagick / GraphicsMagick policy.xml hardened (disable MSL/MVG/EPHEMERAL/HTTPS/TEXT delegates) if used
- [ ] `gm` / `imagemagick-cli` not invoked on raw user filenames via `exec` - use library bindings or argv form
- [ ] PDF / Office document processing in a sandboxed worker (separate process, no network, time-limit)

## 5. Storage Backend

**Checklist:**
- [ ] Local filesystem storage on a partition that does not allow exec (`noexec` mount option) for uploaded files
- [ ] S3 / GCS uploads use server-issued presigned URLs with constrained `Content-Type`, `Content-Length`, key prefix
- [ ] Bucket policy denies public read by default; serve via signed URL or proxy
- [ ] Cross-tenant isolation: bucket / prefix per tenant, IAM scoped accordingly

## 6. Serving Uploaded Files

**Red Flags:**
```js
// VULNERABLE - serving user uploads from express.static causes HTML/JS to execute in your origin
app.use("/uploads", express.static("uploads"));
// attacker uploads HTML with <script>...</script>, links victim - same-origin XSS
```

**Checklist:**
- [ ] User-uploaded content served from a different origin (e.g. `userdata.example.com`) so any XSS is sandboxed
- [ ] OR: served via dedicated route that sets `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
      `Content-Security-Policy: sandbox`, AND a known-safe `Content-Type` (no `text/html`, no `image/svg+xml` without
      sanitize)
- [ ] Image proxy / thumbnail endpoint validates upstream URL via SSRF guard if it fetches external images

## 7. Antivirus / Content Scanning

**Checklist:**
- [ ] If accepting executables, archives, or office docs: integrate ClamAV / commercial scanner before serving
- [ ] Quarantine on detection; do not delete silently (forensics)

## 8. Archive Extraction (zip/tar)

See SKILL.md "Decompression Bombs" for full coverage:
- [ ] No `extractAll` directly; manual loop with path-boundary check (zip slip / tar slip)
- [ ] Tar symlink/hardlink members rejected
- [ ] Per-entry size and total size cap

## References

- OWASP File Upload Cheat Sheet
- ImageTragick: https://imagetragick.com/
