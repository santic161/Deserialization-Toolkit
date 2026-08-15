package burp.core;

import java.util.Base64;
import java.util.List;
import java.nio.charset.StandardCharsets;

/**
 * O(1) magic-byte detector for serialized Java objects in any transport form.
 *
 * <p>A Java {@code ObjectOutputStream} stream always starts with {@code 0xAC 0xED 0x00 0x05}
 * (STREAM_MAGIC + version). That prefix survives every common transport wrapping:
 * <ul>
 *   <li>raw bytes            -> {@code \xac\xed\x00\x05}</li>
 *   <li>Base64               -> {@code rO0AB...}</li>
 *   <li>URL-safe Base64      -> {@code rO0AB...} (same prefix)</li>
 *   <li>ASCII hex            -> {@code aced0005...}</li>
 *   <li>GZIP wrapped Base64  -> {@code H4sIA...} (gzip magic 0x1f 0x8b -> "H4sI")</li>
 * </ul>
 *
 * <p>This lets the passive scanner classify a cookie/parameter value in constant time
 * without ever attempting deserialization.
 */
public final class SerializationDetector {

    private SerializationDetector() {}

    // 0xAC 0xED 0x00 0x05
    private static final byte[] RAW_MAGIC = {(byte) 0xAC, (byte) 0xED, 0x00, 0x05};

    /** Human-readable classification of a value. */
    public enum Kind {
        RAW_JAVA_SERIALIZED,
        BASE64_JAVA_SERIALIZED,
        HEX_JAVA_SERIALIZED,
        GZIP_WRAPPED,       // gzip stream; could wrap a serialized object
        NONE
    }

    public static Kind classify(String value) {
        if (value == null || value.isEmpty()) return Kind.NONE;
        String v = value.trim();

        // Base64 (standard or URL-safe) serialized objects start with rO0.
        if (v.startsWith("rO0")) return Kind.BASE64_JAVA_SERIALIZED;
        // gzip magic base64-encoded.
        if (v.startsWith("H4sI")) return Kind.GZIP_WRAPPED;
        // ASCII hex.
        String lower = v.toLowerCase();
        if (lower.startsWith("aced0005") || lower.startsWith("aced")) return Kind.HEX_JAVA_SERIALIZED;

        // Raw bytes carried in a header/param (ISO-8859-1 round-trip).
        byte[] bytes = v.getBytes(StandardCharsets.ISO_8859_1);
        if (startsWith(bytes, RAW_MAGIC)) return Kind.RAW_JAVA_SERIALIZED;

        // Last resort: value might be Base64 of something that gunzips to a serialized blob.
        if (looksBase64(v) && v.length() > 12) {
            try {
                byte[] decoded = Base64.getDecoder().decode(v);
                if (startsWith(decoded, RAW_MAGIC)) return Kind.BASE64_JAVA_SERIALIZED;
                byte[] maybe = Encoder.gunzip(decoded);
                if (startsWith(maybe, RAW_MAGIC)) return Kind.GZIP_WRAPPED;
            } catch (IllegalArgumentException ignored) { /* not base64 */ }
        }
        return Kind.NONE;
    }

    public static boolean isSerialized(String value) {
        return classify(value) != Kind.NONE;
    }

    /** Framework fingerprint tokens found in a header/cookie name+value pair. */
    public static List<String> fingerprintTokens(String name, String value) {
        String hay = (name + " " + value).toLowerCase();
        return List.of("jsf", "viewstate", "jsessionid", "spring", "grails", "vaadin",
                       "wicket", "seam", "mojarra", "primefaces", "struts", "jboss", "weblogic")
                   .stream().filter(hay::contains).toList();
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }

    private static boolean looksBase64(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                      || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }
}
