package burp.core;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.List;

/**
 * Precise, per-flag JPMS self-check.
 *
 * <p>ysoserial's gadget builder needs several JDK-internal packages either <b>exported</b>
 * (symbolic access to public types like {@code TemplatesImpl}/{@code AbstractTranslet}) or
 * <b>opened</b> (reflective {@code setAccessible} on private fields). On Java 17+ these must be
 * granted with {@code --add-exports}/{@code --add-opens} on Burp's JVM.
 *
 * <p>Instead of printing a generic "add these flags" blob, this checker probes <em>each</em>
 * requirement against the actual ysoserial classloader's unnamed module and prints
 * {@code [PASS]}/{@code [FAIL]} next to the exact flag line, so a missing flag is unambiguous.
 */
public final class JpmsCheck {

    private JpmsCheck() {}

    private enum Kind { OPEN, EXPORT }

    private record Req(Kind kind, String module, String pkg) {
        String flag() {
            String verb = kind == Kind.OPEN ? "--add-opens" : "--add-exports";
            return verb + "=" + module + "/" + pkg + "=ALL-UNNAMED";
        }
    }

    private static final List<Req> REQUIREMENTS = List.of(
        new Req(Kind.OPEN,   "java.base", "java.util"),
        new Req(Kind.OPEN,   "java.base", "java.util.concurrent"),
        new Req(Kind.OPEN,   "java.base", "java.lang"),
        new Req(Kind.OPEN,   "java.base", "java.lang.reflect"),
        new Req(Kind.OPEN,   "java.base", "java.net"),
        new Req(Kind.OPEN,   "java.base", "java.security"),
        new Req(Kind.OPEN,   "java.base", "sun.reflect.annotation"),
        new Req(Kind.OPEN,   "java.management", "javax.management"),
        new Req(Kind.OPEN,   "java.xml",  "com.sun.org.apache.xalan.internal.xsltc.trax"),
        new Req(Kind.OPEN,   "java.rmi",  "sun.rmi.server"),
        new Req(Kind.OPEN,   "java.rmi",  "sun.rmi.transport"),
        new Req(Kind.EXPORT, "java.xml",  "com.sun.org.apache.xalan.internal.xsltc.trax"),
        new Req(Kind.EXPORT, "java.xml",  "com.sun.org.apache.xalan.internal.xsltc.runtime"),
        new Req(Kind.EXPORT, "java.sql.rowset", "com.sun.rowset")
    );

    /** Copy-paste block of every required flag (all lines, in order). */
    public static final String FLAGS = build();

    private static String build() {
        StringBuilder sb = new StringBuilder();
        for (Req r : REQUIREMENTS) sb.append(r.flag()).append('\n');
        return sb.toString().trim();
    }

    /** Coarse gate used elsewhere: is java.base reflection open at all? */
    public static boolean isOpen() {
        try {
            java.util.HashMap.class.getDeclaredField("size").setAccessible(true);
            return true;
        } catch (Throwable t) { return false; }
    }

    /**
     * Probe every requirement against {@code probeLoader}'s unnamed module (the module ysoserial
     * classes actually live in) and log a per-line PASS/FAIL report.
     *
     * @param probeLoader the ysoserial classloader, or null to fall back to this extension's loader
     */
    public static void report(MontoyaApi api, ClassLoader probeLoader) {
        Module target = (probeLoader != null ? probeLoader : JpmsCheck.class.getClassLoader())
                .getUnnamedModule();

        List<String> fails = new ArrayList<>();
        StringBuilder out = new StringBuilder("\n[JDS-NG] ===== JPMS flag self-check =====\n");
        for (Req r : REQUIREMENTS) {
            boolean ok = check(r, target);
            if (!ok) fails.add(r.flag());
            out.append("[JDS-NG] ").append(ok ? "[PASS] " : "[FAIL] ").append(r.flag()).append('\n');
        }

        if (fails.isEmpty()) {
            out.append("[JDS-NG] All required module flags present. Gadget chains can run.");
            api.logging().logToOutput(out.toString());
        } else {
            out.append("[JDS-NG] ").append(fails.size()).append(" flag(s) MISSING. Add the [FAIL] "
                    + "line(s) above to Burp's *.vmoptions (one per line) and RESTART Burp.\n");
            out.append("[JDS-NG] Note: Groovy1 (GroovyBugError) and Clojure (Hackvertor clash) fail "
                    + "regardless of flags — that is ysoserial vs. modern JDK, not a missing flag.");
            api.logging().logToError(out.toString());
        }
    }

    private static boolean check(Req r, Module target) {
        Module m = ModuleLayer.boot().findModule(r.module()).orElse(null);
        if (m == null) return true; // module not present in this JRE => not applicable
        return r.kind() == Kind.OPEN ? m.isOpen(r.pkg(), target) : m.isExported(r.pkg(), target);
    }
}
