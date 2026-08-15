package burp.core;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared, bounded thread pool for active scanning. A single pool (sized from
 * {@link Settings#threads()}) keeps concurrent probes fast without flooding the target
 * or Burp's own worker threads. Daemon threads so a pool never blocks Burp shutdown.
 */
public final class ExecutorProvider {

    private volatile ExecutorService pool;
    private volatile int size = -1;
    private final Settings settings;

    public ExecutorProvider(Settings settings) { this.settings = settings; }

    /** Returns a pool sized to the current setting, rebuilding it if the setting changed. */
    public synchronized ExecutorService pool() {
        int desired = settings.threads();
        if (pool == null || pool.isShutdown() || desired != size) {
            if (pool != null) pool.shutdownNow();
            size = desired;
            pool = Executors.newFixedThreadPool(desired, named("jdsng-scan"));
        }
        return pool;
    }

    public synchronized void shutdown() {
        if (pool != null) pool.shutdownNow();
        pool = null;
    }

    private static ThreadFactory named(String prefix) {
        AtomicInteger n = new AtomicInteger(1);
        return r -> {
            Thread t = new Thread(r, prefix + "-" + n.getAndIncrement());
            t.setDaemon(true);
            return t;
        };
    }
}
