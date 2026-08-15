# Bundled ysoserial jar

Drop the fat ysoserial build here as **`ysoserial-all.jar`** before running `mvn package` to
ship it inside the extension (the "bundled fork" the engine loads by default).

```
src/main/resources/ysoserial/ysoserial-all.jar
```

Why the **`-all`** (fat) jar and not the slim one: gadget chains need the vulnerable libraries
(commons-collections, commons-beanutils, spring, …) on the classpath. The fat jar bundles them;
the slim jar does not and every non-trivial chain would throw `NoClassDefFoundError`.

If you skip this file, the extension still works — just point it at an external
`ysoserial-all.jar` from the **Settings** tab at runtime.

Get ysoserial: https://github.com/frohoff/ysoserial (or a maintained fork).
Build the fat jar with `mvn clean package -DskipTests` — output is `target/ysoserial-all.jar`.
