package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.JpmsCheck;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.core.ExecutorProvider;
import burp.core.Settings;
import burp.core.YsoserialEngine;
import burp.scan.CookiePassiveScanCheck;
import burp.ui.MainTab;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Entry point. Wires the settings, the in-process ysoserial engine, the passive cookie
 * scan check, the suite UI and a context menu that routes any request into the workflow.
 */
public final class JavaDeserializationScannerNG implements BurpExtension {

    private static final String NAME = "Java Deserialization Scanner NG";

    private ExecutorProvider executors;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        Settings settings = new Settings(api);
        YsoserialEngine yso = new YsoserialEngine(api, settings);
        this.executors = new ExecutorProvider(settings);

        // Load ysoserial off the EDT so a slow/large jar never freezes Burp startup.
        new Thread(() -> { yso.reload(); JpmsCheck.report(api, yso.classLoader()); }, "jdsng-init").start();

        MainTab mainTab = new MainTab(api, yso, settings, executors);
        api.userInterface().registerSuiteTab("Deserialization NG", mainTab);
        api.scanner().registerScanCheck(new CookiePassiveScanCheck(api, settings));
        api.userInterface().registerContextMenuItemsProvider(menuProvider(mainTab));
        api.extension().registerUnloadingHandler(() -> executors.shutdown());

        api.logging().logToOutput(NAME + " loaded. Passive cookie scanning "
                + (settings.passiveEnabled() ? "ON" : "OFF") + ".");
    }

    private ContextMenuItemsProvider menuProvider(MainTab mainTab) {
        return new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                HttpRequestResponse rr = pick(event);
                if (rr == null) return List.of();

                List<Component> items = new ArrayList<>();
                JMenuItem toBuilder = new JMenuItem("JDS-NG: Send to Payload Builder");
                toBuilder.addActionListener(e -> { mark(rr, "Payload Builder"); mainTab.sendToBuilder(rr); });
                JMenuItem toScanner = new JMenuItem("JDS-NG: Send to Scanner");
                toScanner.addActionListener(e -> { mark(rr, "Scanner"); mainTab.sendToScanner(rr); });
                items.add(toBuilder);
                items.add(toScanner);
                return items;
            }
        };
    }

    /** Colour the source row orange (like "Send to Repeater") and annotate it. */
    private static void mark(HttpRequestResponse rr, String target) {
        try {
            rr.annotations().setHighlightColor(HighlightColor.ORANGE);
            String prev = rr.annotations().notes();
            String note = "→ JDS-NG " + target;
            rr.annotations().setNotes(prev == null || prev.isBlank() ? note : prev + " | " + note);
        } catch (Exception ignored) { /* transient request-responses may be read-only */ }
    }

    private static HttpRequestResponse pick(ContextMenuEvent event) {
        Optional<?> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            try {
                return ((burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse) editor.get())
                        .requestResponse();
            } catch (Exception ignored) { }
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        return selected.isEmpty() ? null : selected.get(0);
    }
}
