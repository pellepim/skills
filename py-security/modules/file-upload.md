# File Upload Security Patterns

Optional module for the `/security` skill. Apply when the project accepts file uploads from users.

## 1. Path Traversal

**Red Flags:**
```python
# VULNERABLE - user-controlled filename used directly
filepath = os.path.join(UPLOAD_DIR, request.files["doc"].filename)
with open(filepath, "wb") as f:
    f.write(content)
# filename = "../../etc/cron.d/backdoor" -> writes outside UPLOAD_DIR

# SAFE - sanitize and verify
from werkzeug.utils import secure_filename
filename = secure_filename(request.files["doc"].filename)
filepath = os.path.join(UPLOAD_DIR, filename)
# Double-check resolved path is under UPLOAD_DIR
if not os.path.realpath(filepath).startswith(os.path.realpath(UPLOAD_DIR)):
    raise SecurityError("Path traversal")
```

**Checklist:**
- [ ] User-supplied filenames sanitized (strip `..`, `/`, `\`, null bytes)
- [ ] Resolved path verified to be under the intended upload directory (`os.path.realpath`)
- [ ] Generated filenames preferred over user-supplied ones (UUID + original extension)

## 2. MIME / Content Type Validation

**Red Flags:**
```python
# VULNERABLE - trusts client-supplied Content-Type
if request.files["img"].content_type.startswith("image/"):
    save(request.files["img"])  # Could be a .html file with image/png Content-Type

# SAFE - validate actual content
import magic
mime = magic.from_buffer(file_content, mime=True)
if mime not in ALLOWED_MIMES:
    raise ValidationError("Invalid file type")
```

**Checklist:**
- [ ] Never trust `Content-Type` header alone (client-controlled)
- [ ] Validate actual file content (magic bytes / `python-magic` / `filetype`)
- [ ] Extension validated against an allowlist, not a denylist
- [ ] Extension and detected MIME type must agree
- [ ] Double extensions blocked (`.php.jpg`, `.html.png`)

## 3. Size Limits

**Checklist:**
- [ ] Maximum file size enforced at reverse proxy / middleware level (not just application)
- [ ] Per-file and per-request limits (prevent many small files exhausting disk)
- [ ] Streaming upload handling preferred over loading entire file into memory
- [ ] Disk quota per user/tenant if applicable
- [ ] Multipart form data size capped (framework default may be unlimited)

## 4. Storage Isolation

**Checklist:**
- [ ] Uploaded files stored outside the web root (not directly servable)
- [ ] If served, served through an application handler with auth checks (not static file middleware)
- [ ] Files from different tenants/users stored in isolated paths or buckets
- [ ] Uploaded files not executable (filesystem permissions, no execute bit)
- [ ] Storage path does not leak user IDs or internal structure in URLs

## 5. Image Processing Exploits

**Red Flags:**
```python
# VULNERABLE - processing untrusted SVG (can contain JavaScript, XXE)
from cairosvg import svg2png
svg2png(bytestring=user_uploaded_svg)

# VULNERABLE - ImageMagick without policy (ImageTragick CVE-2016-3714)
os.system(f"convert {uploaded_file} output.png")
```

**Checklist:**
- [ ] SVG uploads treated as untrusted XML (sanitize or rasterize in sandbox)
- [ ] Image processing libraries updated (Pillow, ImageMagick, cairosvg)
- [ ] ImageMagick policy.xml restricts delegates if used (no `url`, `ephemeral`, `msl`)
- [ ] Pillow `Image.open()` followed by `verify()` or size check before processing (zip bomb / decompression bomb)
- [ ] Image dimensions capped before processing (prevent memory exhaustion from 100000x100000 pixel images)
- [ ] EXIF data stripped if images are served publicly (can contain GPS, device info)

## 6. Serving Uploaded Files

**Red Flags:**
```python
# VULNERABLE - serves with user-controlled Content-Type
return Response(content, media_type=stored_content_type)  # Could be text/html -> XSS

# SAFE - force download or safe type
return Response(content, media_type="application/octet-stream",
    headers={"Content-Disposition": f"attachment; filename={safe_name}"})
```

**Checklist:**
- [ ] `Content-Disposition: attachment` for downloads (prevents browser rendering)
- [ ] If inline display needed, `Content-Type` set from validated allowlist (not stored user value)
- [ ] `X-Content-Type-Options: nosniff` header set
- [ ] Served from a separate domain/subdomain if inline rendering allowed (isolates XSS)
- [ ] `Content-Security-Policy` on served files restricts script execution

## 7. Temporary Files

**Checklist:**
- [ ] Temporary files cleaned up after processing (in `finally` block or context manager)
- [ ] Temp directory not shared with other users/requests
- [ ] `tempfile.mkstemp()` or `NamedTemporaryFile` used (not predictable filenames)
- [ ] Temp files not world-readable (restrictive umask)

## 8. Anti-Virus / Malware

**Checklist:**
- [ ] If storing files for download by other users, consider AV scanning (ClamAV)
- [ ] Files quarantined until scan completes (not immediately available)
- [ ] Scan failures treated as rejections, not passes
