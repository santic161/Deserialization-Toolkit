package burp.model;

import java.util.Set;

/**
 * A ysoserial payload gadget chain plus the library it needs on the target classpath.
 *
 * <p>Gadgets are discovered dynamically from the loaded ysoserial jar
 * ({@code burp.core.YsoserialEngine}). The static metadata here (required library,
 * whether the chain runs a command, notes) is used by the UI to help the analyst
 * choose a chain and by the recommender to rank chains against passive findings.
 */
public final class Gadget {

    /** ysoserial payload name, e.g. {@code CommonsCollections6}. */
    private final String name;
    /** Human-friendly library this chain depends on, e.g. {@code commons-collections 3.1}. */
    private final String requiredLibrary;
    /** Lower-cased tokens matched against server fingerprints (headers, cookies, errors). */
    private final Set<String> fingerprintTokens;
    /** {@code true} if the chain accepts an OS command as its argument. */
    private final boolean commandCapable;
    private final String notes;

    public Gadget(String name, String requiredLibrary, Set<String> fingerprintTokens,
                  boolean commandCapable, String notes) {
        this.name = name;
        this.requiredLibrary = requiredLibrary;
        this.fingerprintTokens = fingerprintTokens == null ? Set.of() : fingerprintTokens;
        this.commandCapable = commandCapable;
        this.notes = notes == null ? "" : notes;
    }

    public String name() { return name; }
    public String requiredLibrary() { return requiredLibrary; }
    public Set<String> fingerprintTokens() { return fingerprintTokens; }
    public boolean commandCapable() { return commandCapable; }
    public String notes() { return notes; }

    @Override
    public String toString() { return name; }
}
