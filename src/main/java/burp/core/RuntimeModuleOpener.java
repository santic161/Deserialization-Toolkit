package burp.core;

import burp.api.montoya.MontoyaApi;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Opens the JDK-internal packages ysoserial needs <em>at runtime</em>, so the extension works on a
 * stock Burp with <b>no {@code --add-opens}/{@code --add-exports} JVM flags</b>.
 *
 * <p>JVM module flags are normally fixed at startup and an extension loads afterwards, so it cannot
 * set its own {@code vmoptions}. Instead we obtain the JDK's trusted {@code IMPL_LOOKUP} via
 * {@code sun.misc.Unsafe} and call {@code Module.implAddOpensToAllUnnamed} /
 * {@code implAddExportsToAllUnnamed} directly — the same technique ByteBuddy/Lombok use. This grants
 * the exact set of opens/exports {@link JpmsCheck} verifies, to every unnamed module (including the
 * ysoserial classloader's), without touching Burp's launcher.
 *
 * <p>Best-effort: if a future JDK removes these internals the call fails cleanly and the extension
 * falls back to the documented JVM flags (still shown in Settings). Verified working on Java 17–25.
 */
public final class RuntimeModuleOpener {

    private RuntimeModuleOpener() {}

    private record Grant(boolean open, String module, String pkg) {}

    private static final Grant[] GRANTS = {
        new Grant(true,  "java.base", "java.util"),
        new Grant(true,  "java.base", "java.util.concurrent"),
        new Grant(true,  "java.base", "java.lang"),
        new Grant(true,  "java.base", "java.lang.reflect"),
        new Grant(true,  "java.base", "java.net"),
        new Grant(true,  "java.base", "java.security"),
        new Grant(true,  "java.base", "sun.reflect.annotation"),
        new Grant(true,  "java.management", "javax.management"),
        new Grant(true,  "java.xml", "com.sun.org.apache.xalan.internal.xsltc.trax"),
        new Grant(false, "java.xml", "com.sun.org.apache.xalan.internal.xsltc.runtime"),
        new Grant(true,  "java.rmi", "sun.rmi.server"),
        new Grant(true,  "java.rmi", "sun.rmi.transport"),
        new Grant(false, "java.sql.rowset", "com.sun.rowset"),
    };

    /** @return true if the module access was granted (or already present); false if blocked. */
    public static boolean openAll(MontoyaApi api) {
        if (JpmsCheck.isOpen()) {
            // Flags already present (user set vmoptions) — nothing to do.
            return true;
        }
        try {
            MethodHandles.Lookup trusted = trustedLookup();
            MethodHandle addOpens = trusted.unreflect(
                    Module.class.getDeclaredMethod("implAddOpensToAllUnnamed", String.class));
            MethodHandle addExports = trusted.unreflect(
                    Module.class.getDeclaredMethod("implAddExportsToAllUnnamed", String.class));

            for (Grant g : GRANTS) {
                Module m = ModuleLayer.boot().findModule(g.module()).orElse(null);
                if (m == null) continue; // module absent in this JRE
                (g.open() ? addOpens : addExports).invokeWithArguments(m, g.pkg());
            }
            api.logging().logToOutput("[Deser-TK] Runtime module access granted — ysoserial chains run "
                    + "without any JVM flags.");
            return true;
        } catch (Throwable t) {
            api.logging().logToError("[Deser-TK] Runtime module opening unavailable (" + t + "). "
                    + "If gadget chains fail, add the JVM flags listed in the Settings tab and restart Burp.");
            return false;
        }
    }

    /** Grab the JDK's all-access {@code IMPL_LOOKUP} through Unsafe (bypasses module checks). */
    private static MethodHandles.Lookup trustedLookup() throws Exception {
        Class<?> unsafeCls = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeCls.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Object unsafe = theUnsafe.get(null);

        Method staticFieldBase = unsafeCls.getMethod("staticFieldBase", Field.class);
        Method staticFieldOffset = unsafeCls.getMethod("staticFieldOffset", Field.class);
        Method getReference;
        try {
            getReference = unsafeCls.getMethod("getObject", Object.class, long.class);
        } catch (NoSuchMethodException e) {
            getReference = unsafeCls.getMethod("getReference", Object.class, long.class); // newer JDKs
        }

        Field implLookup = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
        Object base = staticFieldBase.invoke(unsafe, implLookup);
        long offset = (long) staticFieldOffset.invoke(unsafe, implLookup);
        return (MethodHandles.Lookup) getReference.invoke(unsafe, base, offset);
    }
}
