package burp.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import java.nio.charset.StandardCharsets;

/**
 * Places an (already-encoded) payload into an arbitrary point of a request — a selected range,
 * the caret, or a {@code {PAYLOAD}} marker — not just a cookie.
 *
 * <p>Two safeguards, because a raw insertion can silently corrupt the whole request:
 * <ul>
 *   <li><b>No stray line breaks</b> — {@link #isTransportSafe} rejects payloads containing
 *       CR/LF/NUL before they are spliced, so a RAW/GZIP payload cannot inject a header break or
 *       truncate the request. Text-safe encodings (Base64, URL-Base64, ASCII-hex) always pass.</li>
 *   <li><b>Content-Length stays correct</b> — after any splice the header is recomputed from the
 *       actual body length, so body insertions don't desync the request.</li>
 * </ul>
 */
final class RequestInserter {

    static final String MARKER = "{PAYLOAD}";

    private RequestInserter() {}

    /** A payload is transport-safe for splicing into a request if it has no CR, LF or NUL. */
    static boolean isTransportSafe(String payload) {
        return payload.indexOf('\r') < 0 && payload.indexOf('\n') < 0 && payload.indexOf('\0') < 0;
    }

    /** Replace bytes [start,end) of the request with {@code payload}. */
    static HttpRequest replaceRange(HttpRequest req, int start, int end, String payload) {
        byte[] bytes = toBytes(req.toByteArray());
        start = clamp(start, 0, bytes.length);
        end = clamp(end, start, bytes.length);
        byte[] p = payload.getBytes(StandardCharsets.ISO_8859_1);

        byte[] out = new byte[start + p.length + (bytes.length - end)];
        System.arraycopy(bytes, 0, out, 0, start);
        System.arraycopy(p, 0, out, start, p.length);
        System.arraycopy(bytes, end, out, start + p.length, bytes.length - end);
        return fixContentLength(HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(out)));
    }

    /** Insert at a caret offset (zero-width range). */
    static HttpRequest insertAt(HttpRequest req, int caret, String payload) {
        return replaceRange(req, caret, caret, payload);
    }

    /**
     * Convert the editor's current selection into a persistent {@code {PAYLOAD}} marker.
     *
     * <p>Captured at click time (while the selection is still valid) and written back into the
     * request text, so later insertion never depends on a live selection that may have been lost —
     * the marked bytes are visibly replaced by the marker and will be overwritten on insert.
     *
     * @return the updated request, or null if there is no request / no selection
     */
    static HttpRequest markSelection(HttpRequestEditor editor) {
        HttpRequest req = editor.getRequest();
        if (req == null) return null;
        var sel = editor.selection();
        if (sel.isEmpty()) return null;
        var range = sel.get().offsets();
        return replaceRange(req, range.startIndexInclusive(), range.endIndexExclusive(), MARKER);
    }

    /** Replace every {@code {PAYLOAD}} marker. Returns null if the marker is absent. */
    static HttpRequest replaceMarker(HttpRequest req, String payload) {
        String wire = new String(toBytes(req.toByteArray()), StandardCharsets.ISO_8859_1);
        if (!wire.contains(MARKER)) return null;
        String replaced = wire.replace(MARKER, payload);
        return fixContentLength(HttpRequest.httpRequest(req.httpService(),
                ByteArray.byteArray(replaced.getBytes(StandardCharsets.ISO_8859_1))));
    }

    // ------------------------------------------------------------------ internals

    private static HttpRequest fixContentLength(HttpRequest req) {
        int bodyLen = req.body().length();
        boolean hasHeader = req.headers().stream().anyMatch(h -> h.name().equalsIgnoreCase("Content-Length"));
        if (hasHeader) return req.withUpdatedHeader("Content-Length", String.valueOf(bodyLen));
        if (bodyLen > 0)  return req.withAddedHeader("Content-Length", String.valueOf(bodyLen));
        return req;
    }

    private static byte[] toBytes(ByteArray ba) {
        int n = ba.length();
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = ba.getByte(i);
        return out;
    }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }
}
