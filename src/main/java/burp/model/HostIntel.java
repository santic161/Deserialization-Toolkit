package burp.model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-host intelligence accumulated across passive scans, active scans and manual tests.
 *
 * <p>This is the memory that powers the gadget recommender: when the analyst opens the
 * Payload Builder for a host, the panel asks {@link #scoreFor} to rank chains by what we
 * already learned about that target (confirmed chains first, then fingerprint matches).
 *
 * <p>All state is thread-safe: passive scan checks run on Burp worker threads while the
 * UI reads on the EDT.
 */
public final class HostIntel {

    private static final HostIntel INSTANCE = new HostIntel();
    public static HostIntel get() { return INSTANCE; }
    private HostIntel() {}

    /** host -> gadget names confirmed vulnerable (highest signal). */
    private final Map<String, Set<String>> confirmedGadgets = new ConcurrentHashMap<>();
    /** host -> fingerprint tokens seen in traffic (framework/library hints). */
    private final Map<String, Set<String>> fingerprints = new ConcurrentHashMap<>();
    /** host -> whether a serialized Java blob was ever observed. */
    private final Map<String, Boolean> sawSerializedBlob = new ConcurrentHashMap<>();

    public void recordConfirmed(String host, String gadget) {
        confirmedGadgets.computeIfAbsent(host, k -> Collections.synchronizedSet(new LinkedHashSet<>())).add(gadget);
    }

    public void recordFingerprint(String host, String token) {
        if (token == null || token.isBlank()) return;
        fingerprints.computeIfAbsent(host, k -> Collections.synchronizedSet(new LinkedHashSet<>()))
                    .add(token.toLowerCase());
    }

    public void recordSerializedBlob(String host) { sawSerializedBlob.put(host, Boolean.TRUE); }

    public boolean hasSerializedBlob(String host) { return sawSerializedBlob.getOrDefault(host, Boolean.FALSE); }

    public Set<String> confirmedGadgets(String host) {
        return Set.copyOf(confirmedGadgets.getOrDefault(host, Set.of()));
    }

    public Set<String> fingerprints(String host) {
        return Set.copyOf(fingerprints.getOrDefault(host, Set.of()));
    }

    /**
     * Rank score for a gadget against a host. Higher = more likely to work.
     * <ul>
     *   <li>+100 already confirmed vulnerable on this host</li>
     *   <li>+10 per fingerprint token that matches the gadget's required library</li>
     *   <li>+1  the host is known to echo serialized blobs at all</li>
     * </ul>
     */
    public int scoreFor(String host, Gadget gadget) {
        int score = 0;
        if (confirmedGadgets.getOrDefault(host, Set.of()).contains(gadget.name())) score += 100;
        Set<String> fp = fingerprints.getOrDefault(host, Set.of());
        for (String token : gadget.fingerprintTokens()) {
            if (fp.contains(token)) score += 10;
        }
        if (hasSerializedBlob(host)) score += 1;
        return score;
    }

    public void clear() {
        confirmedGadgets.clear();
        fingerprints.clear();
        sawSerializedBlob.clear();
    }
}
