package burp.ui;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Replaces (or adds) a single cookie in a request's {@code Cookie} header while leaving the
 * rest of the header untouched. We rewrite the raw header rather than using parameter helpers
 * so already-encoded payload values (Base64, hex, URL-encoded) pass through verbatim.
 */
final class CookieRewriter {

    private CookieRewriter() {}

    static HttpRequest setCookie(HttpRequest req, String name, String value) {
        String existing = null;
        for (var h : req.headers()) {
            if (h.name().equalsIgnoreCase("Cookie")) { existing = h.value(); break; }
        }

        String rebuilt;
        if (existing == null || existing.isBlank()) {
            rebuilt = name + "=" + value;
        } else {
            StringBuilder sb = new StringBuilder();
            boolean replaced = false;
            for (String part : existing.split(";")) {
                String trimmed = part.trim();
                if (trimmed.isEmpty()) continue;
                int eq = trimmed.indexOf('=');
                String cn = eq > 0 ? trimmed.substring(0, eq).trim() : trimmed;
                if (sb.length() > 0) sb.append("; ");
                if (cn.equals(name)) { sb.append(name).append('=').append(value); replaced = true; }
                else sb.append(trimmed);
            }
            if (!replaced) { if (sb.length() > 0) sb.append("; "); sb.append(name).append('=').append(value); }
            rebuilt = sb.toString();
        }

        return existing == null
                ? req.withAddedHeader("Cookie", rebuilt)
                : req.withUpdatedHeader("Cookie", rebuilt);
    }
}
