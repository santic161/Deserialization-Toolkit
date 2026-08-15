package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.ExecutorProvider;
import burp.core.Settings;
import burp.core.YsoserialEngine;

import javax.swing.*;
import java.awt.*;

/** Root suite tab: hosts the Payload Builder, Scanner and Settings sub-tabs. */
public final class MainTab extends JPanel {

    private final JTabbedPane tabs = new JTabbedPane();
    private final PayloadBuilderPanel builder;
    private final ScannerPanel scanner;
    private final SettingsPanel settings;

    public MainTab(MontoyaApi api, YsoserialEngine yso, Settings settingsModel, ExecutorProvider executors) {
        super(new BorderLayout());
        this.builder = new PayloadBuilderPanel(api, yso, settingsModel);
        this.scanner = new ScannerPanel(api, yso, settingsModel, executors);
        this.settings = new SettingsPanel(api, settingsModel, yso, () -> {
            builder.refreshGadgets();
            scanner.refreshGadgets();
        });

        tabs.addTab("Payload Builder", builder);
        tabs.addTab("Scanner", scanner);
        tabs.addTab("Settings", settings);
        add(tabs, BorderLayout.CENTER);
    }

    public void sendToBuilder(HttpRequestResponse rr) {
        builder.loadRequest(rr);
        tabs.setSelectedComponent(builder);
    }

    public void sendToScanner(HttpRequestResponse rr) {
        scanner.loadRequest(rr);
        tabs.setSelectedComponent(scanner);
    }
}
