package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.core.Encoder;
import burp.core.ExecutorProvider;
import burp.core.Settings;
import burp.core.YsoserialEngine;
import burp.model.DetectionResult;
import burp.scan.DeserializationScanEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.function.Function;

/**
 * Active detection against a chosen insertion point (a cookie value). Runs the selected
 * gadget chains concurrently with either a time-based or a Collaborator-DNS strategy and
 * streams results into a table. Confirmed chains flow into the recommender automatically.
 */
public final class ScannerPanel extends JPanel {

    private final MontoyaApi api;
    private final YsoserialEngine yso;
    private final DeserializationScanEngine engine;

    private final HttpRequestEditor requestEditor;
    private final JTextField cookieNameField = new JTextField("session", 14);
    private final JComboBox<Encoder> encodingCombo = new JComboBox<>(Encoder.values());
    private final JRadioButton timeBased = new JRadioButton("Time-based", true);
    private final JRadioButton dnsBased = new JRadioButton("DNS (Collaborator)");
    private final JTextField callbackField = new JTextField("nslookup %s", 16);
    private final JLabel status = new JLabel(" ");
    private final JList<String> gadgetList = new JList<>();
    private final DefaultTableModel results = new DefaultTableModel(
            new Object[]{"Gadget", "Method", "Result", "Evidence"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };

    public ScannerPanel(MontoyaApi api, YsoserialEngine yso, Settings settings, ExecutorProvider executors) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.yso = yso;
        this.engine = new DeserializationScanEngine(api, settings, yso, executors);
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        encodingCombo.setSelectedItem(Encoder.URL_BASE64);

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(buildTop(), BorderLayout.NORTH);
        add(buildCenter(), BorderLayout.CENTER);
        refreshGadgets();
    }

    private JComponent buildTop() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        p.add(new JLabel("Target cookie:"));
        p.add(cookieNameField);
        p.add(new JLabel("Encoding:"));
        p.add(encodingCombo);
        ButtonGroup bg = new ButtonGroup();
        bg.add(timeBased); bg.add(dnsBased);
        p.add(timeBased); p.add(dnsBased);
        p.add(new JLabel("OOB cmd:"));
        callbackField.setToolTipText("Command for library chains in DNS mode; %s = Collaborator host. "
                + "e.g. nslookup %s  |  curl http://%s/  |  ping -c1 %s");
        p.add(callbackField);
        JButton run = new JButton("Run detection");
        JButton clear = new JButton("Clear");
        run.addActionListener(e -> run());
        clear.addActionListener(e -> { results.setRowCount(0); status.setText(" "); });
        p.add(run); p.add(clear);

        status.setForeground(new Color(0x1a7f37));
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(p, BorderLayout.CENTER);
        wrap.add(status, BorderLayout.SOUTH);
        return wrap;
    }

    private JComponent buildCenter() {
        JScrollPane gadgets = new JScrollPane(gadgetList);
        gadgets.setBorder(BorderFactory.createTitledBorder("Gadgets (multi-select; none = all)"));
        gadgets.setPreferredSize(new Dimension(220, 0));

        JSplitPane editorResults = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                titled(requestEditor.uiComponent(), "Request (paste or send from Proxy/Repeater)"),
                new JScrollPane(new JTable(results)));
        editorResults.setResizeWeight(0.55);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, gadgets, editorResults);
        split.setResizeWeight(0.18);
        return split;
    }

    public void loadRequest(HttpRequestResponse rr) {
        if (rr != null && rr.request() != null) requestEditor.setRequest(rr.request());
        refreshGadgets();
    }

    public void refreshGadgets() {
        gadgetList.setListData(yso.availableGadgetNames().toArray(new String[0]));
    }

    private void run() {
        HttpRequest base = requestEditor.getRequest();
        if (base == null) { addRow("-", "-", "ERROR", "No request loaded"); return; }
        if (!yso.isReady() && !yso.reload()) { addRow("-", "-", "ERROR", yso.lastError()); return; }

        String cookie = cookieNameField.getText().trim();
        Encoder enc = (Encoder) encodingCombo.getSelectedItem();
        String host = safeHost(base);
        Function<String, HttpRequest> requestFor = encoded -> CookieRewriter.setCookie(base, cookie, encoded);

        List<String> selected = gadgetList.getSelectedValuesList();

        if (dnsBased.isSelected()) {
            // URLDNS (no library) + command-capable chains (proves RCE out-of-band).
            List<String> pool = selected.isEmpty() ? yso.availableGadgetNames() : selected;
            List<String> oob = pool.stream()
                    .filter(g -> g.equalsIgnoreCase("URLDNS")
                            || burp.core.GadgetCatalog.metadata(g).commandCapable())
                    .toList();
            if (oob.isEmpty()) { addRow("-", "DNS", "ERROR", "no URLDNS/command chains selected"); return; }
            status.setText(" Running " + oob.size() + " chain(s) via Collaborator…");
            engine.collaboratorScan(host, oob, enc, requestFor, callbackField.getText().trim(), this::onResult);
            return;
        }

        if (selected.isEmpty()) selected = yso.availableGadgetNames();
        status.setText(" Running " + selected.size() + " chain(s), time-based…");
        engine.timeBasedScan(host, selected, enc, requestFor, base, this::onResult);
    }

    private void onResult(DetectionResult r) {
        String verdict = r.detail().startsWith("error:") ? "ERROR"
                       : r.vulnerable() ? "VULNERABLE" : "NOT VULNERABLE";
        SwingUtilities.invokeLater(() -> addRow(r.gadget(), r.method().name(), verdict, r.detail()));
    }

    private void addRow(String gadget, String method, String result, String evidence) {
        results.addRow(new Object[]{gadget, method, result, evidence});
    }

    private static String safeHost(HttpRequest req) {
        try { return req.httpService().host(); } catch (Exception e) { return ""; }
    }

    private static JComponent titled(Component comp, String title) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBorder(BorderFactory.createTitledBorder(title));
        wrap.add(comp, BorderLayout.CENTER);
        return wrap;
    }
}
