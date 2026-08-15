package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.core.Settings;
import burp.core.YsoserialEngine;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Settings + first-run help. Lets the analyst point at a newer ysoserial jar, tune the
 * scan engine, and read the "why Java breaks" troubleshooting notes inline.
 */
public final class SettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final Settings settings;
    private final YsoserialEngine yso;
    private final Runnable onGadgetsChanged;

    private final JTextField pathField = new JTextField(40);
    private final JSpinner threads = new JSpinner(new SpinnerNumberModel(4, 1, 32, 1));
    private final JSpinner sleepSecs = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));
    private final JSpinner thresholdMs = new JSpinner(new SpinnerNumberModel(4000, 500, 60000, 250));
    private final JCheckBox passive = new JCheckBox("Enable passive cookie scanning");
    private final JLabel engineStatus = new JLabel();

    public SettingsPanel(MontoyaApi api, Settings settings, YsoserialEngine yso, Runnable onGadgetsChanged) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.settings = settings;
        this.yso = yso;
        this.onGadgetsChanged = onGadgetsChanged;

        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        pathField.setText(settings.ysoserialPath());
        threads.setValue(settings.threads());
        sleepSecs.setValue(settings.sleepSeconds());
        thresholdMs.setValue(settings.timeThresholdMs());
        passive.setSelected(settings.passiveEnabled());

        add(buildForm(), BorderLayout.NORTH);
        add(buildHelp(), BorderLayout.CENTER);
        updateStatus();
    }

    private JComponent buildForm() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;
        c.gridx = 0; c.gridy = row; p.add(new JLabel("ysoserial jar (leave blank = bundled fork):"), c);
        c.gridx = 1; p.add(pathField, c);
        JButton browse = new JButton("Browse…");
        browse.addActionListener(e -> browse());
        c.gridx = 2; p.add(browse, c);

        row++;
        c.gridx = 0; c.gridy = row; p.add(new JLabel("Scan threads:"), c);
        c.gridx = 1; p.add(threads, c);

        row++;
        c.gridx = 0; c.gridy = row; p.add(new JLabel("Time-based sleep (seconds):"), c);
        c.gridx = 1; p.add(sleepSecs, c);

        row++;
        c.gridx = 0; c.gridy = row; p.add(new JLabel("Time-based threshold (ms over baseline):"), c);
        c.gridx = 1; p.add(thresholdMs, c);

        row++;
        c.gridx = 1; c.gridy = row; p.add(passive, c);

        row++;
        JButton apply = new JButton("Apply & reload ysoserial");
        apply.addActionListener(e -> apply());
        c.gridx = 1; c.gridy = row; p.add(apply, c);

        row++;
        engineStatus.setFont(engineStatus.getFont().deriveFont(Font.PLAIN));
        c.gridx = 0; c.gridy = row; c.gridwidth = 3; p.add(engineStatus, c);

        return p;
    }

    private JComponent buildHelp() {
        JEditorPane help = new JEditorPane("text/html", HELP_HTML);
        help.setEditable(false);
        help.setBorder(BorderFactory.createTitledBorder("Setup & troubleshooting"));
        return new JScrollPane(help);
    }

    private void browse() {
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            pathField.setText(f.getAbsolutePath());
        }
    }

    private void apply() {
        settings.setYsoserialPath(pathField.getText().trim());
        settings.setThreads((Integer) threads.getValue());
        settings.setSleepSeconds((Integer) sleepSecs.getValue());
        settings.setTimeThresholdMs((Integer) thresholdMs.getValue());
        settings.setPassiveEnabled(passive.isSelected());
        boolean ok = yso.reload();
        if (onGadgetsChanged != null) onGadgetsChanged.run();
        updateStatus();
        JOptionPane.showMessageDialog(this,
                ok ? "ysoserial reloaded: " + yso.availableGadgetNames().size() + " chains available."
                   : "ysoserial not loaded:\n" + yso.lastError(),
                ok ? "OK" : "Problem", ok ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
    }

    private void updateStatus() {
        if (yso.isReady()) {
            engineStatus.setForeground(new Color(0x1a7f37));
            engineStatus.setText("ysoserial ready — " + yso.availableGadgetNames().size()
                    + " chains from " + yso.loadedFrom());
        } else {
            engineStatus.setForeground(Color.RED.darker());
            engineStatus.setText("ysoserial NOT loaded — " + yso.lastError());
        }
    }

    private static final String HELP_HTML = """
        <html><body style='font-family:sans-serif;font-size:11px'>
        <h3>ysoserial jar</h3>
        <p>Payloads are generated <b>in-process</b> — the extension loads the ysoserial jar with its
        own classloader and never runs <code>java -jar</code>. That means <b>you do not need a working
        <code>java</code> on your PATH</b>, which removes the single most common source of ysoserial errors.</p>
        <ol>
          <li><b>Default:</b> a bundled fork ships inside the extension. Leave the path blank to use it.</li>
          <li><b>Newer fork / extra gadgets:</b> download <code>ysoserial-all.jar</code>
              (the fat build that bundles the vulnerable libraries), Browse to it, then
              <i>Apply &amp; reload</i>. Any chain in that jar becomes selectable.</li>
        </ol>
        <h3>⚠ Every chain fails with InaccessibleObjectException (Java 17+)</h3>
        <p>This is the #1 issue. Java's module system (JPMS) blocks the reflection ysoserial uses.
        Launch Burp's JVM with these <b>--add-opens</b> flags, then restart Burp:</p>
        <pre style='font-size:10px'>--add-opens=java.base/java.util=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
--add-opens=java.base/java.net=ALL-UNNAMED
--add-opens=java.base/java.security=ALL-UNNAMED
--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED
--add-opens=java.management/javax.management=ALL-UNNAMED
--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED
--add-opens=java.rmi/sun.rmi.server=ALL-UNNAMED
--add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED
--add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED
--add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED
--add-exports=java.sql.rowset/com.sun.rowset=ALL-UNNAMED</pre>
        <p>The two <b>--add-exports</b> lines are required for the CommonsCollections / Spring /
        Hibernate / TemplatesImpl chains (<code>IllegalAccessError: ... does not export
        ...xsltc.trax</code>); the <b>--add-opens</b> lines fix the
        <code>InaccessibleObjectException</code> chains.</p>
        <p><b>Where to put them:</b> edit Burp's <code>*.vmoptions</code> file (next to the Burp
        executable, one flag per line), or if you run the jar directly:
        <code>java &lt;flags&gt; -jar burpsuite.jar</code>. On the standalone jar you can also set
        the <code>JAVA_TOOL_OPTIONS</code> env var to the same flags on one line.
        The extension prints a PASS/FAIL check at load in <b>Extensions ▸ Output/Errors</b>.</p>
        <h3>Other Java problems</h3>
        <ul>
          <li><b>"Unable to access jarfile"</b> — path is wrong. Use Browse to avoid typos.</li>
          <li><b>"UnsupportedClassVersionError"</b> — the external jar was built for a newer JDK than
              Burp's JRE. Use the bundled fork, or a jar built for Java 17.</li>
          <li><b>"NoClassDefFoundError" for a gadget's library</b> — you pointed at the small
              <code>ysoserial.jar</code> instead of <code>ysoserial-all.jar</code>. Use the fat jar.</li>
        </ul>
        <h3>Detection tips</h3>
        <ul>
          <li>Start with <b>URLDNS</b> (DNS/Collaborator) — it proves deserialization with no library dependency.</li>
          <li>Then try <b>CommonsCollections6</b> and <b>CommonsBeanutils1</b> — the most broadly reliable chains.</li>
          <li>The Payload Builder orders chains by what the passive scanner already learned about the host.</li>
        </ul>
        </body></html>
        """;
}
