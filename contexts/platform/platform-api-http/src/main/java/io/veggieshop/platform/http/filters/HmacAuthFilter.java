package io.veggieshop.platform.http.filters;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

/**
 * HmacAuthFilter (Servlet)
 *
 * Enterprise-grade HMAC authentication for partner APIs:
 * - Activates only when HMAC headers are present (opt-in).
 * - Verifies timestamp (with clock skew guard) and nonce (replay protection).
 * - Signs (method, path, canonical query, body digest, tenant).
 * - Never logs secrets or PII; exposes an authenticated principal for downstream use.
 *
 * The bean is created by platform-starter-web (auto-config). No Spring stereotype here.
 */
@Order(TenantFilter.ORDER + 15) // runs after tenant resolution
public final class HmacAuthFilter extends OncePerRequestFilter {

    // Canonical tenant header
    private static final String HEADER_TENANT_ID = TenantContext.REQUEST_HEADER;

    // Default HMAC header names (overridable via constructor)
    private final String HDR_KEY_ID;
    private final String HDR_TIMESTAMP;
    private final String HDR_NONCE;         // default: X-Hmac-Nonce
    private final String HDR_SIGNATURE;
    private static final String HDR_DIGEST = "Digest"; // "SHA-256=<base64>"

    public static final String REQUEST_ATTR_PRINCIPAL = HmacAuthFilter.class.getName() + ".PRINCIPAL";

    // ---- Configuration (immutable) ----
    private final HmacKeyResolver keyResolver;
    private final NonceStore nonceStore;
    private final Clock clock;
    private final int maxBodyBytes;
    private final long skewSeconds;
    private final boolean enforceBodySha256;
    private final String macAlgorithm;   // e.g. HmacSHA256
    private final String algLabel;       // e.g. HMAC-SHA256

    // ---- Constructors ----

    /** Preferred constructor used by auto-configuration. */
    public HmacAuthFilter(
            HmacKeyResolver keyResolver,
            NonceStore nonceStore,
            Clock clock,
            String keyIdHeader,
            String timestampHeader,
            String nonceHeader,
            String signatureHeader,
            int maxBodyBytes,
            Duration clockSkew,
            boolean enforceBodySha256,
            String macAlgorithm
    ) {
        this.keyResolver       = Objects.requireNonNull(keyResolver, "HmacKeyResolver");
        this.nonceStore        = Objects.requireNonNull(nonceStore, "NonceStore");
        this.clock             = (clock == null ? Clock.systemUTC() : clock);
        this.HDR_KEY_ID        = headerOrDefault(keyIdHeader, "X-Hmac-Key-Id");
        this.HDR_TIMESTAMP     = headerOrDefault(timestampHeader, "X-Hmac-Timestamp");
        this.HDR_NONCE         = headerOrDefault(nonceHeader, "X-Hmac-Nonce");
        this.HDR_SIGNATURE     = headerOrDefault(signatureHeader, "X-Hmac-Signature");
        this.maxBodyBytes      = Math.max(1024, maxBodyBytes);
        this.skewSeconds       = Math.max(0, (clockSkew == null ? Duration.ofSeconds(120) : clockSkew).toSeconds());
        this.enforceBodySha256 = enforceBodySha256;
        this.macAlgorithm      = (macAlgorithm == null || macAlgorithm.isBlank()) ? "HmacSHA256" : macAlgorithm;
        this.algLabel          = toAlgLabel(this.macAlgorithm); // e.g. HMAC-SHA256
    }

    private static String headerOrDefault(String v, String def) {
        return (v == null || v.isBlank()) ? def : v.trim();
    }

    private static String toAlgLabel(String macAlg) {
        String suffix = macAlg.startsWith("Hmac") ? macAlg.substring(4) : macAlg;
        return "HMAC-" + suffix;
    }

    // ---- Filter logic ----

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        // Skip CORS preflight
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null) {
            return true;
        }
        // Activate only if HMAC headers are present
        return !(request.getHeader(HDR_KEY_ID) != null || request.getHeader(HDR_SIGNATURE) != null);
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        // Resolve tenant (from TenantContext or header)
        final TenantId tenantId = resolveTenantOrThrow(request);

        // 1) HMAC headers
        final String keyId        = trimOrNull(request.getHeader(HDR_KEY_ID));
        final String timestampStr = trimOrNull(request.getHeader(HDR_TIMESTAMP));
        final String nonce        = trimOrNull(request.getHeader(HDR_NONCE));
        final String signatureB64 = trimOrNull(request.getHeader(HDR_SIGNATURE));
        final String digestHeader = trimOrNull(request.getHeader(HDR_DIGEST));

        if (keyId == null || timestampStr == null || nonce == null || signatureB64 == null) {
            setWwwAuthenticate(response, "invalid_request", "Missing HMAC headers");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Missing HMAC headers")
                    .captureStackTrace(false)
                    .build();
        }
        if (nonce.length() < 8) {
            setWwwAuthenticate(response, "invalid_request", "Nonce too short");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Nonce too short")
                    .captureStackTrace(false)
                    .build();
        }

        // 2) Timestamp + clock skew
        final long now = clock.instant().getEpochSecond();
        final long ts;
        try { ts = Long.parseLong(timestampStr); }
        catch (NumberFormatException e) {
            setWwwAuthenticate(response, "invalid_request", "Invalid timestamp");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Invalid timestamp")
                    .captureStackTrace(false)
                    .build();
        }
        if (Math.abs(now - ts) > skewSeconds) {
            setWwwAuthenticate(response, "invalid_token", "Stale timestamp");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Request timestamp outside allowed clock skew")
                    .captureStackTrace(false)
                    .build();
        }

        // 3) Resolve key + tenant scope
        final HmacKey key = keyResolver.find(keyId)
                .orElseThrow(() -> {
                    setWwwAuthenticate(response, "invalid_token", "Unknown key");
                    return VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                            .detail("Unknown HMAC key")
                            .captureStackTrace(false)
                            .build();
                });
        if (!key.isActive()) {
            setWwwAuthenticate(response, "invalid_token", "Key disabled");
            throw VeggieException.builder(ProblemTypes.AUTHORIZATION_DENIED)
                    .detail("HMAC key disabled")
                    .captureStackTrace(false)
                    .build();
        }
        if (!key.allowedTenants().isEmpty() && !key.allowedTenants().contains(tenantId.value())) {
            setWwwAuthenticate(response, "insufficient_scope", "Tenant not allowed for this key");
            throw VeggieException.builder(ProblemTypes.AUTHORIZATION_DENIED)
                    .detail("Tenant not allowed for this HMAC key")
                    .captureStackTrace(false)
                    .build();
        }

        // 4) Nonce replay protection
        final String nonceKey = key.keyId() + "|" + tenantId.value() + "|" + nonce;
        if (!nonceStore.register(nonceKey, ts)) {
            setWwwAuthenticate(response, "invalid_token", "Replay detected");
            throw VeggieException.builder(ProblemTypes.AUTHORIZATION_DENIED)
                    .detail("Replay detected")
                    .captureStackTrace(false)
                    .build();
        }

        // 5) Body (cache if needed)
        HttpServletRequest effectiveRequest = request;
        byte[] body = new byte[0];
        if (mayHaveBody(request.getMethod())) {
            body = readBodyBytesLimited(request.getInputStream());
            effectiveRequest = new CachedBodyRequestWrapper(request, body);
        }

        // Digest (optional, or required if configured)
        String computedDigest = (body.length == 0) ? "-" : base64(sha256(body));
        if (enforceBodySha256) {
            String expected = "SHA-256=" + computedDigest;
            if (digestHeader == null || !expected.equals(digestHeader)) {
                setWwwAuthenticate(response, "invalid_request", "Digest required or mismatch");
                throw VeggieException.builder(ProblemTypes.VALIDATION_FAILED)
                        .detail("Digest header required or mismatch")
                        .captureStackTrace(false)
                        .build();
            }
        }

        // 6) String to sign
        final String method = request.getMethod().toUpperCase(Locale.ROOT);
        final String path   = rawPath(request);
        final String query  = canonicalQueryString(request.getQueryString());
        final String stringToSign = buildStringToSign(algLabel, ts, nonce, method, path, query, computedDigest, tenantId.value());

        final byte[] expectedSig  = hmac(macAlgorithm, key.secret(), stringToSign.getBytes(StandardCharsets.UTF_8));
        final byte[] presentedSig = decodeBase64(signatureB64);

        if (!constantTimeEquals(expectedSig, presentedSig)) {
            setWwwAuthenticate(response, "invalid_token", "Signature mismatch");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("HMAC signature mismatch")
                    .captureStackTrace(false)
                    .build();
        }

        // 7) Success → expose principal
        HmacPrincipal principal = new HmacPrincipal(
                key.keyId(), tenantId.value(), key.partnerId().orElse(null), key.scopes(), key.roles()
        );
        effectiveRequest.setAttribute(REQUEST_ATTR_PRINCIPAL, principal);

        try {
            response.setHeader("X-Auth-Strategy", "HMAC");
            chain.doFilter(effectiveRequest, response);
        } finally {
            effectiveRequest.removeAttribute(REQUEST_ATTR_PRINCIPAL);
        }
    }

    // ---- Canonicalization & crypto ----

    private TenantId resolveTenantOrThrow(HttpServletRequest request) {
        // Prefer TenantContext (set by TenantFilter), else header
        var present = TenantContext.currentTenantId();
        if (present.isPresent()) return present.get();

        String hdr = firstHeaderValue(request.getHeader(HEADER_TENANT_ID));
        if (hdr == null || hdr.isBlank()) {
            throw VeggieException.builder(ProblemTypes.TENANT_REQUIRED)
                    .detail("Missing required header: " + HEADER_TENANT_ID)
                    .captureStackTrace(false)
                    .build();
        }
        try {
            return TenantId.of(hdr.trim());
        } catch (IllegalArgumentException ex) {
            throw VeggieException.builder(ProblemTypes.TENANT_UNKNOWN)
                    .detail("Invalid " + HEADER_TENANT_ID + " value")
                    .cause(ex)
                    .captureStackTrace(false)
                    .build();
        }
    }

    private static String buildStringToSign(String algLabel, long ts, String nonce, String method, String path,
                                            String canonicalQuery, String digestB64, String tenantId) {
        return new StringBuilder(256)
                .append(algLabel).append('\n')
                .append("ts:").append(ts).append('\n')
                .append("nonce:").append(nonce).append('\n')
                .append("meth:").append(method).append('\n')
                .append("path:").append(path).append('\n')
                .append("query:").append(canonicalQuery).append('\n')
                .append("digest:").append(digestB64).append('\n')
                .append("tenant:").append(tenantId)
                .toString();
    }

    private static String rawPath(HttpServletRequest req) {
        String p = req.getRequestURI();
        return p != null ? p : "/";
    }

    private static boolean mayHaveBody(String method) {
        return switch (method.toUpperCase(Locale.ROOT)) {
            case "POST", "PUT", "PATCH", "DELETE" -> true;
            default -> false;
        };
    }

    private static String canonicalQueryString(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) return "";
        List<Map.Entry<String, String>> pairs = new ArrayList<>();
        for (String part : rawQuery.split("&")) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            String k = eq >= 0 ? part.substring(0, eq) : part;
            String v = eq >= 0 ? part.substring(eq + 1) : "";
            try {
                k = URLDecoder.decode(k, StandardCharsets.UTF_8);
                v = URLDecoder.decode(v, StandardCharsets.UTF_8);
            } catch (Exception ignore) {}
            pairs.add(Map.entry(k, v));
        }
        pairs.sort(Comparator.<Map.Entry<String,String>, String>comparing(Map.Entry::getKey)
                .thenComparing(Map.Entry::getValue));
        return pairs.stream()
                .map(e -> urlEncode(e.getKey()) + "=" + urlEncode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String urlEncode(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if (isUnreserved(c)) out.append(c);
            else out.append('%').append(String.format("%02X", (int) c));
        }
        return out.toString();
    }

    private static boolean isUnreserved(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    private static byte[] sha256(byte[] body) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(body);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] hmac(String macAlg, byte[] secret, byte[] data) {
        try {
            Mac mac = Mac.getInstance(macAlg);
            mac.init(new SecretKeySpec(secret, macAlg));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(macAlg + " not available", e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] decodeBase64(String b64) {
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= a[i] ^ b[i];
        return r == 0;
    }

    private static String trimOrNull(String s) { return (s == null) ? null : s.trim(); }

    private static String firstHeaderValue(String v) {
        if (v == null) return null;
        int comma = v.indexOf(',');
        return (comma >= 0 ? v.substring(0, comma) : v).trim();
    }

    private static void setWwwAuthenticate(HttpServletResponse res, String error, String desc) {
        res.setHeader("WWW-Authenticate", "HMAC error=\"" + error + "\", error_description=\"" + desc + "\"");
    }

    private byte[] readBodyBytesLimited(InputStream in) throws IOException {
        Objects.requireNonNull(in, "request input stream");
        byte[] buf = new byte[Math.min(8192, maxBodyBytes)];
        ByteBuffer out = ByteBuffer.allocate(Math.min(65536, maxBodyBytes));
        int read, total = 0;
        while ((read = in.read(buf)) != -1) {
            total += read;
            if (total > maxBodyBytes) {
                throw VeggieException.builder(ProblemTypes.PAYLOAD_TOO_LARGE)
                        .detail("Request body exceeds HMAC verification limit (" + maxBodyBytes + " bytes)")
                        .captureStackTrace(false)
                        .build();
            }
            if (out.remaining() < read) {
                int newCap = Math.min(Math.max(out.capacity() * 2, out.capacity() + read), maxBodyBytes);
                ByteBuffer bigger = ByteBuffer.allocate(newCap);
                out.flip(); bigger.put(out); out = bigger;
            }
            out.put(buf, 0, read);
        }
        out.flip();
        byte[] bytes = new byte[out.remaining()];
        out.get(bytes);
        return bytes;
    }

    // ---- Request wrapper (cached body) ----
    private static final class CachedBodyRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] cached;
        CachedBodyRequestWrapper(HttpServletRequest request, byte[] cached) {
            super(request);
            this.cached = (cached != null ? cached : new byte[0]);
        }
        @Override public ServletInputStream getInputStream() {
            final ByteArrayInputStream bais = new ByteArrayInputStream(cached);
            return new ServletInputStream() {
                @Override public int read() { return bais.read(); }
                @Override public boolean isFinished() { return bais.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener readListener) { /* no-op */ }
            };
        }
        @Override public int getContentLength() { return cached.length; }
        @Override public long getContentLengthLong() { return cached.length; }
    }

    // ---- SPI ----

    /** Immutable view of an HMAC key. */
    public interface HmacKey {
        String keyId();
        byte[] secret();
        boolean isActive();
        Set<String> allowedTenants();  // empty => all tenants
        Optional<String> partnerId();  // optional
        Set<String> roles();
        Set<String> scopes();
    }

    /** Resolves an HMAC key by keyId (typically backed by a secrets store or vault). */
    public interface HmacKeyResolver {
        Optional<HmacKey> find(String keyId);
    }

    /** Nonce store for replay protection. Prefer Redis/CRDT in production. */
    public interface NonceStore {
        /** Registers (keyId|tenant|nonce) and returns false if already seen within TTL. */
        boolean register(String compositeKey, long timestampSeconds);
    }

    /** In-memory NonceStore (useful as a default via the starter). */
    public static NonceStore inMemoryNonceStore(int maxEntries, Duration ttl) {
        return new InMemoryNonceStore(maxEntries, ttl);
    }

    private static final class InMemoryNonceStore implements NonceStore {
        private final ConcurrentHashMap<String, Long> map = new ConcurrentHashMap<>();
        private final int maxEntries;
        private final long ttlNanos;
        InMemoryNonceStore(int maxEntries, Duration ttl) {
            this.maxEntries = Math.max(10_000, maxEntries);
            this.ttlNanos   = Math.max(60, ttl.getSeconds()) * 1_000_000_000L;
        }
        @Override public boolean register(String key, long tsSec) {
            long now = System.nanoTime();
            if (map.size() > maxEntries) prune(now);
            return map.putIfAbsent(key, now) == null;
        }
        private void prune(long now) {
            int target = Math.max(1, map.size() / 10), removed = 0;
            for (var it = map.entrySet().iterator(); it.hasNext() && removed < target; ) {
                var e = it.next();
                if (now - e.getValue() > ttlNanos) { it.remove(); removed++; }
            }
            while (removed < target && !map.isEmpty()) {
                int skip = ThreadLocalRandom.current().nextInt(Math.max(1, map.size()));
                var it2 = map.entrySet().iterator();
                for (int i = 0; i < skip && it2.hasNext(); i++) it2.next();
                if (it2.hasNext()) { it2.next(); it2.remove(); removed++; } else break;
            }
        }
    }

    /** Authenticated principal for HMAC requests. Exposed via REQUEST_ATTR_PRINCIPAL. */
    public static final class HmacPrincipal {
        private final String keyId;
        private final String tenantId;
        private final String partnerId;
        private final Set<String> scopes;
        private final Set<String> roles;
        public HmacPrincipal(String keyId, String tenantId, String partnerId, Set<String> scopes, Set<String> roles) {
            this.keyId = keyId; this.tenantId = tenantId; this.partnerId = partnerId;
            this.scopes = (scopes == null ? Set.of() : Set.copyOf(scopes));
            this.roles  = (roles  == null ? Set.of() : Set.copyOf(roles));
        }
        public String keyId() { return keyId; }
        public String tenantId() { return tenantId; }
        public Optional<String> partnerId() { return Optional.ofNullable(partnerId); }
        public Set<String> scopes() { return scopes; }
        public Set<String> roles()  { return roles; }
    }
}
