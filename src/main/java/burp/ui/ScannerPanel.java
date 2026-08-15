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
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.function.Function;

/**
 * Active detection against a chosen insertion point — a cookie value or a {@code {PAYLOAD}} marker.
 * Runs the selected chains concurrently (time-based or Collaborator-DNS) and streams verdicts into
 * a table. Vulnerable rows are highlighted red and can be sent to the Payload Builder as an exploit
 * in one click. Confirmed chains also flow into the recommender.
 */
public final class ScannerPanel extends JPanel {

    /** Hands a confirmed chain off to the Payload Builder, pre-configured to fire. */
    public interface ExploitSender {
        void send(HttpRequest base, String gadget, Encoder enc, boolean cookieMode, String cookieName);
    }

    private static final String INS_COOKIE = "Cookie";
    private static final String INS_MARKER = "{PAYLOAD} marker";

    private final MontoyaApi api;
    private final YsoserialEngine yso;
    private final DeserializationScanEngine engine;
    private final ExploitSender exploitSender;

    private final HttpRequestEditor requestEditor;
    private final JComboBox<String> insertModeCombo = new JComboBox<>(new String[]{INS_COOKIE, INS_MARKER});
    private final JTextField cookieNameField = new JTextField("session", 10);
    private final JComboBox<Encoder> encodingCombo = new JComboBox<>(Encoder.values());
    private final JRadioButton timeBased = new JRadioButton("Time-based", true);
    private final JRadioButton dnsBased = new JRadioButton("DNS (Collaborator)");
    private final JTextField callbackField = new JTextField("nslookup %s", 14);
    private final JLabel status = new JLabel(" ");
    private final JList<String> gadgetList = new JList<>();

    private final DefaultTableModel results = new DefaultTableModel(
            new Object[]{"Gadget", "Method", "Result", "Evidence"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable resultsTable = new JTable(results) {
        @Override public Component prepareRenderer(TableCellRenderer r, int row, int col) {
            Component c = super.prepareRenderer(r, row, col);
            if (!isRowSelected(row)) {
                Object v = getValueAt(row, 2);
                c.setForeground("VULNERABLE".equals(v) ? new Color(0xE53935)
                                : UIManager.getColor("Table.foreground"));
            }
            return c;
        }
    };

    // Snapshot of the last run, reused when sending a hit to the exploit tab.
    private HttpRequest lastBase;
    private Encoder lastEnc;
    private boolean lastCookieMode;
    private String lastCookieName = "";

    public ScannerPanel(MontoyaApi api, YsoserialEngine yso, Settings settings,
                        ExecutorProvider executors, ExploitSender exploitSender) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.yso = yso;
        this.exploitSender = exploitSender;
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
        p.add(new JLabel("Insert into:"));
        p.add(insertModeCombo);
        p.add(cookieNameField);
        JButton markSel = new JButton("Mark selection");
        markSel.setToolTipText("Replace the selected bytes in the request with a " + RequestInserter.MARKER
                + " marker (used by '{PAYLOAD} marker' mode).");
        markSel.addActionListener(e -> onMarkSelection());
        p.add(markSel);

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
        JButton exploit = new JButton("Send to Exploit");
        run.addActionListener(e -> run());
        clear.addActionListener(e -> { results.setRowCount(0); status.setText(" "); });
        exploit.addActionListener(e -> sendSelectedToExploit());
        p.add(run); p.add(clear); p.add(exploit);

        insertModeCombo.addActionListener(e ->
                cookieNameField.setVisible(INS_COOKIE.equals(insertModeCombo.getSelectedItem())));

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

        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // Clean grid: the default bright cell borders look noisy in Burp's dark theme.
        resultsTable.setShowGrid(false);
        resultsTable.setIntercellSpacing(new Dimension(0, 0));
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setRowHeight(Math.max(20, resultsTable.getRowHeight()));
        resultsTable.getTableHeader().setReorderingAllowed(false);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        // double-click a row -> send to exploit
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) sendSelectedToExploit();
            }
        });
        // right-click -> context menu
        JPopupMenu popup = new JPopupMenu();
        JMenuItem send = new JMenuItem("Send to Exploit (Payload Builder)");
        send.addActionListener(a -> sendSelectedToExploit());
        popup.add(send);
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybePopup(e); }
            private void maybePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = resultsTable.rowAtPoint(e.getPoint());
                if (row >= 0) resultsTable.setRowSelectionInterval(row, row);
                popup.show(resultsTable, e.getX(), e.getY());
            }
        });

        JSplitPane editorResults = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                titled(requestEditor.uiComponent(), "Request (paste/send from Proxy/Repeater; 'Mark selection' for a marker)"),
                new JScrollPane(resultsTable));
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

    private void onMarkSelection() {
        HttpRequest marked = RequestInserter.markSelection(requestEditor);
        if (marked == null) { setStatus("Select some bytes in the request first.", true); return; }
        requestEditor.setRequest(marked);
        insertModeCombo.setSelectedItem(INS_MARKER);
        setStatus("Insert point set: selection replaced with " + RequestInserter.MARKER, false);
    }

    private void run() {
        HttpRequest base = requestEditor.getRequest();
        if (base == null) { addRow("-", "-", "ERROR", "No request loaded"); return; }
        if (!yso.isReady() && !yso.reload()) { addRow("-", "-", "ERROR", yso.lastError()); return; }

        boolean cookieMode = INS_COOKIE.equals(insertModeCombo.getSelectedItem());
        String cookie = cookieNameField.getText().trim();
        Encoder enc = (Encoder) encodingCombo.getSelectedItem();
        String host = safeHost(base);

        if (cookieMode && cookie.isEmpty()) { addRow("-", "-", "ERROR", "Enter a cookie name"); return; }
        if (!cookieMode && RequestInserter.replaceMarker(base, "x") == null) {
            addRow("-", "-", "ERROR", "No " + RequestInserter.MARKER
                    + " marker — select bytes and click 'Mark selection'"); return;
        }

        Function<String, HttpRequest> requestFor = cookieMode
                ? encoded -> CookieRewriter.setCookie(base, cookie, encoded)
                : encoded -> { HttpRequest r = RequestInserter.replaceMarker(base, encoded); return r == null ? base : r; };

        // Snapshot for the exploit hand-off.
        lastBase = base; lastEnc = enc; lastCookieMode = cookieMode; lastCookieName = cookie;

        List<String> selected = gadgetList.getSelectedValuesList();

        if (dnsBased.isSelected()) {
            List<String> pool = selected.isEmpty() ? yso.availableGadgetNames() : selected;
            List<String> oob = pool.stream()
                    .filter(g -> g.equalsIgnoreCase("URLDNS")
                            || burp.core.GadgetCatalog.metadata(g).commandCapable())
                    .toList();
            if (oob.isEmpty()) { addRow("-", "DNS", "ERROR", "no URLDNS/command chains selected"); return; }
            setStatus("Running " + oob.size() + " chain(s) via Collaborator…", false);
            engine.collaboratorScan(host, oob, enc, requestFor, callbackField.getText().trim(), this::onResult);
            return;
        }

        if (selected.isEmpty()) selected = yso.availableGadgetNames();
        setStatus("Running " + selected.size() + " chain(s), time-based…", false);
        engine.timeBasedScan(host, selected, enc, requestFor, base, this::onResult);
    }

    private void onResult(DetectionResult r) {
        boolean error = r.detail().startsWith("error:");
        String verdict = error ? "ERROR" : r.vulnerable() ? "VULNERABLE" : "NOT VULNERABLE";
        // Keep the table quiet: the full stack/cause is already in Extensions > Errors.
        String evidence = error ? "Java error — see Extensions ▸ Errors" : r.detail();
        SwingUtilities.invokeLater(() -> addRow(r.gadget(), r.method().name(), verdict, evidence));
    }

    private void sendSelectedToExploit() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) { setStatus("Select a result row first.", true); return; }
        String gadget = String.valueOf(results.getValueAt(row, 0));
        if (lastBase == null || gadget.isBlank() || gadget.equals("-") || gadget.equals("(batch)")) {
            setStatus("No exploitable gadget on that row.", true); return;
        }
        exploitSender.send(lastBase, gadget, lastEnc, lastCookieMode, lastCookieName);
    }

    private void addRow(String gadget, String method, String result, String evidence) {
        results.addRow(new Object[]{gadget, method, result, evidence});
    }

    private void setStatus(String msg, boolean error) {
        status.setForeground(error ? Color.RED.darker() : new Color(0x1a7f37));
        status.setText(" " + msg);
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
