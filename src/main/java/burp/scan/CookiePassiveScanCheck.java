package burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.core.Settings;
import burp.core.SerializationDetector;
import burp.model.HostIntel;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Passive check that flags insecure cookies. Two families of issue:
 * <ol>
 *   <li><b>Serialized Java object in a cookie</b> (HIGH) — the value carries a serialized
 *       blob (any transport encoding). This is the direct lead for the Payload Builder,
 *       so the finding is also fed into {@link HostIntel} to seed the recommender.</li>
 *   <li><b>Weak cookie flags</b> (LOW/INFO) — missing {@code Secure}, {@code HttpOnly} or
 *       {@code SameSite} on cookies that look session/stateful.</li>
 * </ol>
 *
 * <p>Everything here is constant-time string work (no deserialization, no network), so it
 * adds negligible overhead to Burp's passive pipeline.
 */
public final class CookiePassiveScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final Settings settings;

    public CookiePassiveScanCheck(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse rr) {
        if (!settings.passiveEnabled() || rr == null) return auditResult(List.of());

        List<AuditIssue> issues = new ArrayList<>();
        String host = hostOf(rr);
        String baseUrl = baseUrlOf(rr);
        boolean https = baseUrl.startsWith("https");

        // --- Response Set-Cookie headers -------------------------------------------
        if (rr.response() != null) {
            for (HttpHeader h : rr.response().headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                inspectSetCookie(h.value(), host, baseUrl, https, rr, issues);
            }
        }

        // --- Request Cookie header (values the client sends back) -------------------
        if (rr.request() != null) {
            for (HttpHeader h : rr.request().headers()) {
                if (!h.name().equalsIgnoreCase("Cookie")) continue;
                for (String pair : h.value().split(";")) {
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    String name = pair.substring(0, eq).trim();
                    String value = pair.substring(eq + 1).trim();
                    recordAndMaybeFlagSerialized(name, value, host, baseUrl, rr, issues);
                }
            }
        }

        return auditResult(issues);
    }

    private void inspectSetCookie(String setCookie, String host, String baseUrl, boolean https,
                                  HttpRequestResponse rr, List<AuditIssue> issues) {
        String[] parts = setCookie.split(";");
        if (parts.length == 0) return;

        int eq = parts[0].indexOf('=');
        String name = eq > 0 ? parts[0].substring(0, eq).trim() : parts[0].trim();
        String value = eq > 0 ? parts[0].substring(eq + 1).trim() : "";

        boolean secure = false, httpOnly = false, sameSite = false;
        for (int i = 1; i < parts.length; i++) {
            String a = parts[i].trim().toLowerCase();
            if (a.equals("secure")) secure = true;
            else if (a.equals("httponly")) httpOnly = true;
            else if (a.startsWith("samesite")) sameSite = true;
        }

        recordAndMaybeFlagSerialized(name, value, host, baseUrl, rr, issues);

        // Weak-flag reporting is scoped to stateful-looking cookies to cut noise.
        if (looksStateful(name)) {
            List<String> missing = new ArrayList<>();
            if (https && !secure) missing.add("Secure");
            if (!httpOnly) missing.add("HttpOnly");
            if (!sameSite) missing.add("SameSite");
            if (!missing.isEmpty()) {
                issues.add(AuditIssue.auditIssue(
                    "Insecure cookie flags: " + name,
                    "The cookie <b>" + esc(name) + "</b> is set without: <b>" + String.join(", ", missing)
                        + "</b>. Session/stateful cookies without these attributes are exposed to "
                        + "theft (missing Secure/HttpOnly) or CSRF (missing SameSite).",
                    "Set the missing attributes on the <code>Set-Cookie</code> header.",
                    baseUrl,
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    "Cookies carrying session or authentication state should always be marked "
                        + "<code>Secure</code>, <code>HttpOnly</code> and <code>SameSite</code>.",
                    "Configure the framework's cookie settings or the reverse proxy to add the flags.",
                    AuditIssueSeverity.LOW,
                    rr));
            }
        }
    }

    private void recordAndMaybeFlagSerialized(String name, String value, String host, String baseUrl,
                                              HttpRequestResponse rr, List<AuditIssue> issues) {
        // Feed the recommender regardless of whether we raise an issue.
        for (String token : SerializationDetector.fingerprintTokens(name, value)) {
            HostIntel.get().recordFingerprint(host, token);
        }

        SerializationDetector.Kind kind = SerializationDetector.classify(value);
        if (kind == SerializationDetector.Kind.NONE) return;

        HostIntel.get().recordSerializedBlob(host);

        issues.add(AuditIssue.auditIssue(
            "Serialized Java object in cookie: " + name,
            "The cookie <b>" + esc(name) + "</b> carries a <b>serialized Java object</b> ("
                + kind + "). If the server deserializes it without validation the application is "
                + "likely vulnerable to Java deserialization RCE. Use the <i>Payload Builder</i> tab "
                + "to weaponise this insertion point.",
            "Do not deserialize attacker-controlled data. Sign+encrypt state cookies (e.g. HMAC), "
                + "or replace native serialization with a safe format (JSON/Protobuf) and a look-ahead "
                + "ObjectInputStream allow-list.",
            baseUrl,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.TENTATIVE,
            "Java native serialization in a client-controlled cookie is a classic deserialization sink "
                + "(see PortSwigger's 'Insecure deserialization' labs).",
            "Adopt a signed/opaque session token; deserialize only trusted, validated input.",
            AuditIssueSeverity.HIGH,
            rr));
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        // Active deserialization probing lives in the extension's own Scanner tab, not here.
        return auditResult(List.of());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
                && newIssue.baseUrl().equals(existingIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    // ------------------------------------------------------------------ helpers

    private static boolean looksStateful(String name) {
        String n = name.toLowerCase();
        return n.contains("session") || n.contains("sess") || n.contains("auth")
            || n.contains("token") || n.contains("jsessionid") || n.contains("sid")
            || n.contains("remember") || n.contains("id");
    }

    private static String hostOf(HttpRequestResponse rr) {
        try { return rr.request().httpService().host(); } catch (Exception e) { return ""; }
    }

    private static String baseUrlOf(HttpRequestResponse rr) {
        try { return rr.request().url(); } catch (Exception e) { return ""; }
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
