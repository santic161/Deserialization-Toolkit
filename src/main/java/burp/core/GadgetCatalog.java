package burp.core;

import burp.model.Gadget;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Static metadata for known ysoserial gadget chains.
 *
 * <p>The list of chains actually available at runtime is read from the loaded ysoserial
 * jar (see {@link YsoserialEngine#availableGadgetNames()}). This catalog enriches those
 * names with the library each chain needs and fingerprint tokens for the recommender.
 *
 * <p>Beyond the ~13 libraries of the original extension, this catalog covers the full
 * modern ysoserial set plus several chains added by more recent forks (CommonsBeanutils,
 * C3P0, Click, Vaadin, MozillaRhino, ROME, Clojure, JBossInterceptors, Hibernate,
 * Myfaces, AspectJWeaver). New chains only need a row here to become recommendable.
 */
public final class GadgetCatalog {

    private static final Map<String, Gadget> BY_NAME = new LinkedHashMap<>();

    private static void add(String name, String lib, boolean cmd, Set<String> fp, String notes) {
        BY_NAME.put(name, new Gadget(name, lib, fp, cmd, notes));
    }

    static {
        // --- Library-free ------------------------------------------------------------
        add("URLDNS", "none (JRE only)", false, Set.of(),
            "No command execution. Best first probe: triggers a DNS lookup via Collaborator.");
        add("JRMPClient", "none (JRE only)", false, Set.of(),
            "Outbound JRMP connection; pairs with ysoserial's JRMPListener.");

        // --- Apache Commons Collections ---------------------------------------------
        add("CommonsCollections1", "commons-collections 3.1", true, Set.of("struts", "jboss"), "InvokerTransformer; <=3.2.1.");
        add("CommonsCollections2", "commons-collections4 4.0", true, Set.of(), "PriorityQueue / TemplatesImpl.");
        add("CommonsCollections3", "commons-collections 3.1", true, Set.of("struts", "jboss"), "TemplatesImpl variant.");
        add("CommonsCollections4", "commons-collections4 4.0", true, Set.of(), "collections4 TemplatesImpl.");
        add("CommonsCollections5", "commons-collections 3.1", true, Set.of("struts", "jboss"), "BadAttributeValueExpException; no static init needed.");
        add("CommonsCollections6", "commons-collections 3.1", true, Set.of("struts", "jboss"), "Most reliable CC chain (HashSet/TiedMapEntry).");
        add("CommonsCollections7", "commons-collections 3.1", true, Set.of(), "Hashtable variant.");

        // --- Commons Beanutils / Bsh / Groovy ---------------------------------------
        add("CommonsBeanutils1", "commons-beanutils 1.9.2", true, Set.of("spring"), "Works without commons-collections.");
        add("BeanShell1", "bsh 2.0b5", true, Set.of(), "BeanShell interpreter chain.");
        add("Groovy1", "groovy 2.3.9", true, Set.of("grails", "groovy"), "ConvertedClosure/MethodClosure.");

        // --- Spring -----------------------------------------------------------------
        add("Spring1", "spring-core / spring-beans 4.1.4", true, Set.of("spring", "grails"), "MethodInvokeTypeProvider.");
        add("Spring2", "spring-core / spring-aop 4.1.4", true, Set.of("spring"), "AOP-based variant.");

        // --- Hibernate --------------------------------------------------------------
        add("Hibernate1", "hibernate-core", true, Set.of("hibernate"), "Requires a JDBC driver on classpath.");
        add("Hibernate2", "hibernate-core", true, Set.of("hibernate"), "Alternate TypedValue path.");

        // --- ROME / JSON / Rhino ----------------------------------------------------
        add("ROME", "rome 1.0", true, Set.of("rome"), "ToStringBean chain.");
        add("JSON1", "multiple JSON libs", true, Set.of("json"), "Broad JSON gadget bundle.");
        add("MozillaRhino1", "rhino 1.7R2", true, Set.of("rhino"), "NativeError chain.");
        add("MozillaRhino2", "rhino 1.7.7", true, Set.of("rhino"), "Newer Rhino variant.");

        // --- App-server / connection-pool / misc ------------------------------------
        add("C3P0", "c3p0 0.9.5.2", false, Set.of("c3p0"), "Special arg format <base_url>:<class>; not usable with plain time-based probing.");
        add("Click1", "click-nodeps 2.3.0", true, Set.of("click"), "Apache Click column comparator.");
        add("Vaadin1", "vaadin 7.7.14", true, Set.of("vaadin"), "NestedMethodProperty chain.");
        add("Clojure", "clojure 1.8.0", true, Set.of("clojure"), "AbstractTableModel/PersistentArrayMap.");
        add("JBossInterceptors1", "javassist + jboss-interceptor", true, Set.of("jboss"), "InterceptorMethodHandler.");
        add("Myfaces1", "myfaces", true, Set.of("jsf", "myfaces"), "JSF MyFaces EL chain.");
        add("AspectJWeaver", "aspectjweaver + commons-collections", false, Set.of(), "Special arg format <filename>:<base64>; not usable with plain time-based probing.");
        add("Jdk7u21", "none (JDK <= 7u21)", true, Set.of(), "TemplatesImpl; no external library.");
        add("Jdk8u20", "none (JDK <= 8u20)", true, Set.of(), "Extends Jdk7u21 past the 7u21 fix.");
    }

    /** Metadata for a chain, or a permissive default when the chain is not catalogued. */
    public static Gadget metadata(String name) {
        return BY_NAME.getOrDefault(name,
            new Gadget(name, "unknown", Set.of(), true, "No catalogue entry; treat as command-capable."));
    }

    public static Map<String, Gadget> all() { return Map.copyOf(BY_NAME); }
}
