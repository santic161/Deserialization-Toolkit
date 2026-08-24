package burp.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Output encodings for a generated payload. Mirrors the encodings supported by the
 * original extension and adds URL-safe Base64 and full URL-encoding, which are the two
 * forms most commonly needed when a payload rides inside a cookie or query parameter.
 */
public enum Encoder {
    RAW("Raw"),
    BASE64("Base64"),
    URL_BASE64("Base64 (URL-encoded)"),
    ASCII_HEX("ASCII Hex"),
    GZIP("GZIP"),
    BASE64_GZIP("Base64 + GZIP"),
    URL_BASE64_GZIP("Base64 + GZIP (URL-encoded)");

    private final String label;
    Encoder(String label) { this.label = label; }
    public String label() { return label; }
    @Override public String toString() { return label; }

    /** Encode raw serialized bytes into the transport form for this encoding. */
    public String encode(byte[] raw) {
        try {
            return switch (this) {
                case RAW              -> new String(raw, StandardCharsets.ISO_8859_1);
                case BASE64           -> Base64.getEncoder().encodeToString(raw);
                case URL_BASE64       -> urlEncode(Base64.getEncoder().encodeToString(raw));
                case ASCII_HEX        -> toHex(raw);
                case GZIP             -> new String(gzip(raw), StandardCharsets.ISO_8859_1);
                case BASE64_GZIP      -> Base64.getEncoder().encodeToString(gzip(raw));
                case URL_BASE64_GZIP  -> urlEncode(Base64.getEncoder().encodeToString(gzip(raw)));
            };
        } catch (IOException e) {
            throw new IllegalStateException("Encoding failed: " + e.getMessage(), e);
        }
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String toHex(byte[] raw) {
        StringBuilder sb = new StringBuilder(raw.length * 2);
        for (byte b : raw) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] gzip(byte[] raw) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) { gz.write(raw); }
        return bos.toByteArray();
    }

    /** Best-effort gunzip helper used when fingerprinting inbound blobs. */
    public static byte[] gunzip(byte[] data) {
        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return gz.readAllBytes();
        } catch (IOException e) {
            return data; // not gzipped; return as-is
        }
    }
}
