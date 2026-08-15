package burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

/**
 * User-configurable settings, persisted in Burp's project/user preferences so they
 * survive restarts. Every getter falls back to a sensible default.
 */
public final class Settings {

    private static final String K_YSO_PATH   = "jdsng.ysoserial.path";
    private static final String K_THREADS    = "jdsng.threads";
    private static final String K_TIME_MS    = "jdsng.timebased.thresholdMs";
    private static final String K_SLEEP_SEC  = "jdsng.timebased.sleepSeconds";
    private static final String K_PASSIVE    = "jdsng.passive.enabled";

    private final Preferences prefs;

    public Settings(MontoyaApi api) {
        this.prefs = api.persistence().preferences();
    }

    /** Path to an external ysoserial jar. Empty => use the bundled fork from resources. */
    public String ysoserialPath() {
        String v = prefs.getString(K_YSO_PATH);
        return v == null ? "" : v;
    }
    public void setYsoserialPath(String path) { prefs.setString(K_YSO_PATH, path == null ? "" : path); }

    /** Worker threads for active scanning. Defaults to CPU count, clamped to [1, 32]. */
    public int threads() {
        Integer v = prefs.getInteger(K_THREADS);
        int def = Math.max(1, Math.min(32, Runtime.getRuntime().availableProcessors()));
        return v == null ? def : Math.max(1, Math.min(32, v));
    }
    public void setThreads(int n) { prefs.setInteger(K_THREADS, Math.max(1, Math.min(32, n))); }

    /** Extra delay (ms) over baseline that flags a time-based hit. */
    public int timeThresholdMs() {
        Integer v = prefs.getInteger(K_TIME_MS);
        return v == null ? 4000 : v;
    }
    public void setTimeThresholdMs(int ms) { prefs.setInteger(K_TIME_MS, ms); }

    /** Sleep injected by time-based payloads, in seconds. */
    public int sleepSeconds() {
        Integer v = prefs.getInteger(K_SLEEP_SEC);
        return v == null ? 5 : v;
    }
    public void setSleepSeconds(int s) { prefs.setInteger(K_SLEEP_SEC, s); }

    public boolean passiveEnabled() {
        Boolean v = prefs.getBoolean(K_PASSIVE);
        return v == null || v;
    }
    public void setPassiveEnabled(boolean on) { prefs.setBoolean(K_PASSIVE, on); }
}
