package burp.model;

/** Outcome of a single detection probe (one gadget, one insertion point). */
public final class DetectionResult {

    public enum Method { TIME_BASED, DNS_COLLABORATOR, CPU_BASED, PASSIVE }

    private final String host;
    private final String gadget;
    private final Method method;
    private final boolean vulnerable;
    private final long evidenceMillis;   // response delay for TIME_BASED / CPU_BASED
    private final String detail;

    public DetectionResult(String host, String gadget, Method method,
                           boolean vulnerable, long evidenceMillis, String detail) {
        this.host = host;
        this.gadget = gadget;
        this.method = method;
        this.vulnerable = vulnerable;
        this.evidenceMillis = evidenceMillis;
        this.detail = detail == null ? "" : detail;
    }

    public String host() { return host; }
    public String gadget() { return gadget; }
    public Method method() { return method; }
    public boolean vulnerable() { return vulnerable; }
    public long evidenceMillis() { return evidenceMillis; }
    public String detail() { return detail; }
}
