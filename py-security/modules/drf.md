---
name: Django REST Framework Security Patterns
description: permission_classes defaults, serializer field whitelisting, throttling, ViewSet auth gaps
applies_to:
  - framework: drf
  - dependency: djangorestframework
version: 1
last_updated: 2026-04-29
---

# Django REST Framework Security Patterns

Apply when the project uses DRF. Load alongside `django.md`.

## 1. Default Permissions

**Red Flags:**
```python
# settings.py - VULNERABLE
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
}
# Every view without an explicit permission_classes is OPEN.

# VULNERABLE - default missing entirely (DRF defaults to AllowAny)
REST_FRAMEWORK = {}

# SAFE - default deny, opt-in to public
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}
```

**Checklist:**
- [ ] `DEFAULT_PERMISSION_CLASSES` is `IsAuthenticated` (or stricter) — never `AllowAny` as default
- [ ] Public endpoints opt in explicitly: `permission_classes = [AllowAny]`
- [ ] `DEFAULT_AUTHENTICATION_CLASSES` set explicitly (don't rely on defaults that change between versions)

## 2. ViewSet / View Permission Audits

**Red Flags:**
```python
# VULNERABLE - view forgot permission_classes; falls back to default which may be AllowAny
class InternalDataView(APIView):
    def get(self, request): ...

# VULNERABLE - permission_classes overridden to AllowAny without justification
class UserViewSet(ModelViewSet):
    permission_classes = [AllowAny]   # for one action, but applies to ALL actions
    queryset = User.objects.all()

# SAFE - per-action permissions
class UserViewSet(ModelViewSet):
    def get_permissions(self):
        if self.action == "register":
            return [AllowAny()]
        return [IsAuthenticated()]
```

**Checklist:**
- [ ] Every view either inherits from a default-protected base OR declares `permission_classes`
- [ ] `AllowAny` overrides documented per occurrence (comment with reason)
- [ ] `ModelViewSet` actions audited individually — `list` and `create` have different threat profiles
- [ ] Object-level permissions (`has_object_permission`) implemented for ownership checks; do not rely on `get_queryset`
      filtering alone (returns 404 for non-owners, but does not block direct PUT/PATCH/DELETE if the queryset is
      bypassed)
- [ ] `IsAuthenticatedOrReadOnly` reviewed — anonymous GET may leak data not meant to be public

## 3. Serializer Field Whitelisting

**Red Flags:**
```python
# VULNERABLE - exposes all fields including is_staff, is_superuser, last_login
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"

# VULNERABLE - read_only fields can still be set if bypassed via signal or admin
class UserSerializer(ModelSerializer):
    is_admin = BooleanField(read_only=True)   # client cannot set, but model.save() still respects it

# SAFE
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]
        read_only_fields = ["id", "username"]
```

**Checklist:**
- [ ] No `fields = "__all__"` on write-capable serializers
- [ ] `exclude = [...]` patterns audited — easy to forget to add new sensitive fields here
- [ ] Read-only fields explicitly listed (`read_only_fields`)
- [ ] Sensitive fields (`is_staff`, `is_superuser`, `password`, `tenant_id`) never in `fields` for client-facing
      serializers
- [ ] Separate input and output serializers when their shapes diverge

## 4. Object-Level Permissions / IDOR

**Red Flags:**
```python
# VULNERABLE - get_queryset returns all, no per-object check
class DocumentViewSet(ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]
    # GET /documents/123/ returns ANY document if user is authenticated

# SAFE
class DocumentViewSet(ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated, IsOwner]

    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

**Checklist:**
- [ ] `get_queryset` filters by request user / tenant for owned-resource viewsets
- [ ] `permission_classes` includes an object-level permission (`IsOwner`, `IsTenantMember`) that implements
      `has_object_permission`
- [ ] DRF's `get_object()` calls `check_object_permissions` (default behavior); custom `retrieve` overrides re-call it
- [ ] Nested router lookups (`/users/<id>/documents/`) verify the parent ownership, not just the child

## 5. Throttling / Rate Limits

**Red Flags:**
```python
# VULNERABLE - no throttle on auth endpoints
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request): ...
```

**Checklist:**
- [ ] `DEFAULT_THROTTLE_CLASSES` set with anon and user rates
- [ ] Login / register / password-reset endpoints have a stricter `throttle_classes` (per-IP and per-username)
- [ ] Throttle scope per endpoint configured (`throttle_scope = "login"`) so one endpoint's burst doesn't exhaust
      another's budget
- [ ] Throttle backed by a shared cache (Redis) in multi-instance deployments — local-memory throttle is per-process

## 6. Browsable API in Production

**Checklist:**
- [ ] `DEFAULT_RENDERER_CLASSES` does not include `BrowsableAPIRenderer` in production (or restricted by `IsAdminUser`)
- [ ] Browsable API form does not auto-render fields containing sensitive data

## 7. Pagination / Mass Data Export

**Checklist:**
- [ ] `DEFAULT_PAGINATION_CLASS` set; no list endpoint returns unbounded result sets
- [ ] `max_page_size` capped (defend against `?page_size=999999` exfil)
- [ ] CSV / Excel export endpoints have explicit row caps and stream the response

## 8. Authentication Token Storage

**Checklist:**
- [ ] DRF `TokenAuthentication` tokens hashed in DB (not stored plaintext) — DRF default stores plaintext; consider
      `dj-rest-auth` or custom
- [ ] JWT auth (if using `djangorestframework-simplejwt`): rotation enabled, blacklist app installed for revocation,
      short access-token TTL
- [ ] Session auth and token auth not both enabled on the same view unless intentional (CSRF surface)

## References

- DRF permissions: https://www.django-rest-framework.org/api-guide/permissions/
- DRF throttling: https://www.django-rest-framework.org/api-guide/throttling/
