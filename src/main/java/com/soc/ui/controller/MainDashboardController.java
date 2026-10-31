package com.soc.ui.controller;

import com.soc.detection.InMemoryAlertRepository;
import com.soc.detection.DetectionRuleSettings;
import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.model.RiskLevel;
import com.soc.network.capture.ImportSummary;
import com.soc.network.capture.PcapFileReader;
import com.soc.network.capture.PcapImportService;
import com.soc.network.capture.PcapReadConfig;
import javafx.fxml.FXML;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainDashboardController {
    private static final Logger LOGGER = LoggerFactory.getLogger(MainDashboardController.class);
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
    private static final PcapReadConfig PCAP_LIMITS = PcapReadConfig.defaults();

    @FXML
    private BorderPane root;
    @FXML
    private CheckBox darkThemeToggle;
    @FXML
    private TableView<IntrusionAlert> alertTable;
    @FXML
    private TableColumn<IntrusionAlert, String> alertTimeColumn;
    @FXML
    private TableColumn<IntrusionAlert, String> alertSourceColumn;
    @FXML
    private TableColumn<IntrusionAlert, String> alertTypeColumn;
    @FXML
    private TableColumn<IntrusionAlert, RiskLevel> severityColumn;
    @FXML
    private TableView<NetworkPacket> trafficTable;
    @FXML
    private TableColumn<NetworkPacket, String> trafficTimeColumn;
    @FXML
    private TableColumn<NetworkPacket, String> trafficSourceColumn;
    @FXML
    private TableColumn<NetworkPacket, String> trafficDestinationColumn;
    @FXML
    private TableColumn<NetworkPacket, String> trafficProtocolColumn;
    @FXML
    private TableColumn<NetworkPacket, Number> trafficLengthColumn;
    @FXML
    private TableColumn<NetworkPacket, String> trafficFlagsColumn;
    @FXML
    private TableColumn<NetworkPacket, String> trafficDnsColumn;
    @FXML
    private Label selectedFileLabel;
    @FXML
    private Label importInfoLabel;
    @FXML
    private Label importStatusLabel;
    @FXML
    private Label sourceStatusLabel;
    @FXML
    private Label engineStatusLabel;
    @FXML
    private Label packetsValue;
    @FXML
    private Label alertsValue;
    @FXML
    private Label criticalAlertsValue;
    @FXML
    private Label sourceIpsValue;
    @FXML
    private ProgressBar importProgressBar;
    @FXML
    private Button startImportButton;
    @FXML
    private Button cancelImportButton;
    @FXML
    private Button chooseFileButton;
    @FXML
    private CheckBox portScanEnabled;
    @FXML
    private CheckBox synEnabled;
    @FXML
    private CheckBox icmpEnabled;
    @FXML
    private TextField portScanThreshold;
    @FXML
    private TextField synThreshold;
    @FXML
    private TextField icmpThreshold;
    @FXML
    private TextField observationWindow;

    private final ObservableList<IntrusionAlert> alerts = FXCollections.observableArrayList();
    private final ObservableList<NetworkPacket> traffic = FXCollections.observableArrayList();
    private final InMemoryAlertRepository alertRepository = new InMemoryAlertRepository();
    private final PcapImportService importService = new PcapImportService(PCAP_LIMITS, alertRepository);
    private final ExecutorService importExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "sentinel-pcap-import");
        thread.setDaemon(true);
        return thread;
    });
    private Path selectedFile;
    private Task<ImportSummary> activeImport;

    @FXML
    private void initialize() {
        alertTimeColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(TIMESTAMP_FORMAT.format(cell.getValue().timestamp())));
        alertSourceColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().sourceAddress().orElse("—")));
        alertTypeColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().ruleId()));
        severityColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleObjectProperty<>(cell.getValue().severity()));
        severityColumn.setCellFactory(column -> new TableCell<>() {
            @Override
            protected void updateItem(RiskLevel severity, boolean empty) {
                super.updateItem(severity, empty);
                if (empty || severity == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(severity.name());
                    setStyle("-fx-text-fill: " + severity.getColorHex() + "; -fx-font-weight: bold;");
                }
            }
        });
        alertTable.setItems(alerts);
        trafficTimeColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(TIMESTAMP_FORMAT.format(cell.getValue().timestamp())));
        trafficSourceColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().sourceAddress().orElse("—")));
        trafficDestinationColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().destinationAddress().orElse("—")));
        trafficProtocolColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().protocol().name()));
        trafficLengthColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleLongProperty(cell.getValue().packetLength()));
        trafficFlagsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(
                        cell.getValue().tcpFlags().map(Object::toString).orElse("—")));
        trafficDnsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().dnsQueryName().orElse("—")));
        trafficTable.setItems(traffic);
        cancelImportButton.setDisable(true);
        importProgressBar.setProgress(0);
    }

    @FXML
    private void handleChooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select classic PCAP capture");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Classic PCAP (*.pcap)", "*.pcap"));
        Window owner = root.getScene() == null ? null : root.getScene().getWindow();
        File chosen = chooser.showOpenDialog(owner);
        if (chosen == null) {
            return;
        }

        Path candidate = chosen.toPath();
        try {
            if (!Files.isRegularFile(candidate) || !Files.isReadable(candidate)) {
                throw new IOException("Selected file does not exist or cannot be read.");
            }
            long size = Files.size(candidate);
            if (size > PCAP_LIMITS.maxFileBytes()) {
                throw new IOException("File exceeds the 512 MiB import limit.");
            }
            selectedFile = candidate;
            selectedFileLabel.setText(candidate.getFileName().toString());
            importInfoLabel.setText(formatBytes(size) + " · Classic PCAP / Ethernet");
            importStatusLabel.setText("Ready to import");
            startImportButton.setDisable(false);
        } catch (IOException exception) {
            selectedFile = null;
            startImportButton.setDisable(true);
            importStatusLabel.setText("File validation failed: " + exception.getMessage());
        }
    }

    @FXML
    private void handleStartImport() {
        if (selectedFile == null || activeImport != null) {
            return;
        }
        DetectionRuleSettings ruleSettings;
        try {
            ruleSettings = new DetectionRuleSettings(
                    parseThreshold(portScanThreshold, "Port scan"),
                    parseThreshold(synThreshold, "SYN"),
                    parseThreshold(icmpThreshold, "ICMP"),
                    parseThreshold(observationWindow, "Observation window"),
                    portScanEnabled.isSelected(),
                    synEnabled.isSelected(),
                    icmpEnabled.isSelected());
        } catch (IllegalArgumentException exception) {
            importStatusLabel.setText("Rule configuration error: " + exception.getMessage());
            return;
        }
        Path importPath = selectedFile;
        UUID importId = UUID.randomUUID();
        Task<ImportSummary> task = new Task<>() {
            @Override
            protected ImportSummary call() throws Exception {
                updateMessage("Validating PCAP header...");
                return importService.importFile(
                        importPath,
                        importId,
                        ruleSettings,
                        this::isCancelled,
                        (bytesRead, fileSize, packetCount) -> {
                            updateProgress(bytesRead, fileSize);
                            updateMessage("Reading packet " + packetCount + " · " + formatBytes(bytesRead)
                                    + " of " + formatBytes(fileSize));
                        });
            }
        };
        activeImport = task;
        setImportRunning(true);
        importStatusLabel.textProperty().unbind();
        importStatusLabel.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(event -> {
            importStatusLabel.textProperty().unbind();
            ImportSummary result = task.getValue();
            traffic.setAll(result.trafficSample());
            alerts.setAll(alertRepository.findAll());
            packetsValue.setText(Long.toString(result.packetsParsed()));
            alertsValue.setText(Integer.toString(alerts.size()));
            criticalAlertsValue.setText(Long.toString(alerts.stream()
                    .filter(alert -> alert.severity() == RiskLevel.CRITICAL).count()));
            sourceIpsValue.setText(Integer.toString(result.trackedSources()));
            sourceStatusLabel.setText("SOURCE IMPORTED");
            engineStatusLabel.setText("ENGINE READY");
            importStatusLabel.setText("Completed: " + result.packetsRead() + " records, "
                    + result.packetsParsed() + " parsed, " + result.unsupportedPackets()
                    + " unsupported, " + result.malformedPackets() + " malformed, "
                    + result.alertsGenerated() + " alerts generated, "
                    + result.latePacketsDropped() + " late packets excluded.");
            importProgressBar.setProgress(1);
            activeImport = null;
            setImportRunning(false);
        });
        task.setOnCancelled(event -> {
            importStatusLabel.textProperty().unbind();
            importStatusLabel.setText("Import cancelled. No partial alerts were saved.");
            activeImport = null;
            setImportRunning(false);
        });
        task.setOnFailed(event -> {
            importStatusLabel.textProperty().unbind();
            Throwable failure = task.getException();
            String message = failure == null ? "Unknown import error" : failure.getMessage();
            importStatusLabel.setText("Import failed: " + message);
            LOGGER.error("PCAP import task failed for '{}': {}",
                    importPath.getFileName(), message, failure);
            activeImport = null;
            setImportRunning(false);
        });
        importProgressBar.progressProperty().unbind();
        importProgressBar.progressProperty().bind(task.progressProperty());
        importExecutor.execute(task);
    }

    @FXML
    private void handleCancelImport() {
        if (activeImport != null) {
            activeImport.cancel(true);
        }
    }

    @FXML
    private void handleShowAlertDetails(MouseEvent event) {
        if (event.getClickCount() < 2) {
            return;
        }
        IntrusionAlert selected = alertTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }
        Alert detail = new Alert(Alert.AlertType.INFORMATION);
        detail.setTitle("Detection evidence");
        detail.setHeaderText(selected.ruleId() + " · " + selected.severity());
        detail.setContentText(selected.description() + "\n\n" + selected.evidence()
                + "\n\nStatus: " + AlertStatus.NEW
                + "\nImport ID: " + selected.importId());
        detail.showAndWait();
    }

    public void shutdown() {
        if (activeImport != null) {
            activeImport.cancel(true);
        }
        importExecutor.shutdownNow();
    }

    @FXML
    private void handleThemeChanged() {
        if (root.getScene() == null) {
            return;
        }

        String stylesheet = darkThemeToggle.isSelected() ? "dark.css" : "light.css";
        URL resource = MainDashboardController.class.getResource("/com/soc/ui/css/" + stylesheet);
        if (resource == null) {
            LOGGER.error("Theme stylesheet '{}' was not found", stylesheet);
            return;
        }
        root.getScene().getStylesheets().setAll(resource.toExternalForm());
        LOGGER.info("Application theme changed to {}", darkThemeToggle.isSelected() ? "dark" : "light");
    }

    private void setImportRunning(boolean running) {
        chooseFileButton.setDisable(running);
        startImportButton.setDisable(running || selectedFile == null);
        cancelImportButton.setDisable(!running);
        portScanEnabled.setDisable(running);
        synEnabled.setDisable(running);
        icmpEnabled.setDisable(running);
        portScanThreshold.setDisable(running);
        synThreshold.setDisable(running);
        icmpThreshold.setDisable(running);
        observationWindow.setDisable(running);
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }

    private static long parseThreshold(TextField field, String ruleName) {
        try {
            long threshold = Long.parseLong(field.getText().trim());
            if (threshold <= 0) {
                throw new IllegalArgumentException(ruleName + " threshold must be greater than zero.");
            }
            return threshold;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(ruleName + " threshold must be a whole number.", exception);
        }
    }
}
