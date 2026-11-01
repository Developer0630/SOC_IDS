package com.soc.ui.controller;

import com.soc.detection.DetectionRuleSettings;
import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.model.ObservedEndpoint;
import com.soc.model.RiskLevel;
import com.soc.network.capture.ImportSummary;
import com.soc.network.capture.LiveCaptureInterface;
import com.soc.network.capture.LiveCaptureService;
import com.soc.network.capture.LiveCaptureSnapshot;
import com.soc.network.capture.LiveCaptureState;
import com.soc.network.capture.LivePacketSource;
import com.soc.network.capture.Pcap4jLivePacketSource;
import com.soc.network.capture.PcapFileReader;
import com.soc.network.capture.PcapImportService;
import com.soc.network.capture.PcapReadConfig;
import com.soc.persistence.ImportPersistence;
import com.soc.persistence.ImportSession;
import com.soc.persistence.PersistenceException;
import javafx.fxml.FXML;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
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
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

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
    private TableView<ImportSession> importHistoryTable;
    @FXML
    private TableColumn<ImportSession, String> historyStartedColumn;
    @FXML
    private TableColumn<ImportSession, String> historyFileColumn;
    @FXML
    private TableColumn<ImportSession, String> historyStatusColumn;
    @FXML
    private TableColumn<ImportSession, Number> historyRecordsColumn;
    @FXML
    private TableColumn<ImportSession, Number> historyAlertsColumn;
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
    private TableView<ObservedEndpoint> endpointTable;
    @FXML
    private TableColumn<ObservedEndpoint, String> endpointIpColumn;
    @FXML
    private TableColumn<ObservedEndpoint, String> endpointMacColumn;
    @FXML
    private TableColumn<ObservedEndpoint, Number> endpointPacketsColumn;
    @FXML
    private TableColumn<ObservedEndpoint, String> endpointFirstSeenColumn;
    @FXML
    private TableColumn<ObservedEndpoint, String> endpointLastSeenColumn;
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
    private Label captureStatusLabel;
    @FXML
    private Label captureStatusBarLabel;
    @FXML
    private Label captureMetricsLabel;
    @FXML
    private Label interfaceHelpLabel;
    @FXML
    private Label databaseStatusLabel;
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
    private Button saveRulesButton;
    @FXML
    private ComboBox<LiveCaptureInterface> captureInterfaceCombo;
    @FXML
    private Button refreshInterfacesButton;
    @FXML
    private Button startCaptureButton;
    @FXML
    private Button stopCaptureButton;
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
    private final ObservableList<ImportSession> importHistory = FXCollections.observableArrayList();
    private final ObservableList<ObservedEndpoint> observedEndpoints = FXCollections.observableArrayList();
    private final ImportPersistence persistence;
    private final String persistenceFailure;
    private final PcapImportService importService;
    private final LivePacketSource livePacketSource;
    private final LiveCaptureService liveCaptureService;
    private final ExecutorService captureControlExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "sentinel-capture-control");
        thread.setDaemon(true);
        return thread;
    });
    private final ExecutorService importExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "sentinel-pcap-import");
        thread.setDaemon(true);
        return thread;
    });
    private Path selectedFile;
    private Task<ImportTaskResult> activeImport;
    private AtomicBoolean importCancellation;
    private boolean closed;
    private boolean persistenceReady;
    private LiveCaptureState lastCaptureState = LiveCaptureState.IDLE;

    public MainDashboardController(
            ImportPersistence persistence,
            DetectionRuleSettings initialRuleSettings,
            String persistenceFailure) {
        this.persistence = persistence;
        this.persistenceFailure = persistenceFailure;
        this.importService = persistence == null ? null : new PcapImportService(PCAP_LIMITS, persistence);
        this.livePacketSource = new Pcap4jLivePacketSource();
        this.liveCaptureService = persistence == null ? null : new LiveCaptureService(
                persistence,
                livePacketSource,
                snapshot -> {
                    try {
                        Platform.runLater(() -> {
                            if (!closed) {
                                applyLiveCaptureSnapshot(snapshot);
                            }
                        });
                    } catch (IllegalStateException exception) {
                        LOGGER.debug("JavaFX toolkit stopped before the final capture status update");
                    }
                });
        this.initialRuleSettings = initialRuleSettings;
    }

    private final DetectionRuleSettings initialRuleSettings;

    @FXML
    private void initialize() {
        alertTimeColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(TIMESTAMP_FORMAT.format(cell.getValue().timestamp())));
        alertSourceColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().sourceAddress().orElse("—")));
        alertTypeColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(
                        cell.getValue().ruleId() + " · " + cell.getValue().ruleName()));
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
        historyStartedColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(
                        TIMESTAMP_FORMAT.format(cell.getValue().startedAt())));
        historyFileColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().fileName()));
        historyStatusColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().status().name()));
        historyRecordsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleLongProperty(cell.getValue().totalRecords()));
        historyAlertsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleLongProperty(cell.getValue().alertsCreated()));
        importHistoryTable.setItems(importHistory);
        importHistoryTable.getSelectionModel().selectedItemProperty().addListener(
                (observable, previous, selected) -> {
                    if (selected != null) {
                        showImportAlerts(selected.id());
                    }
                });
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
        endpointIpColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().ipAddress()));
        endpointMacColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().macAddress().orElse("—")));
        endpointPacketsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleLongProperty(cell.getValue().packetsSeen()));
        endpointFirstSeenColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(
                        TIMESTAMP_FORMAT.format(cell.getValue().firstSeen())));
        endpointLastSeenColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(
                        TIMESTAMP_FORMAT.format(cell.getValue().lastSeen())));
        endpointTable.setItems(observedEndpoints);
        cancelImportButton.setDisable(true);
        chooseFileButton.setDisable(true);
        saveRulesButton.setDisable(true);
        stopCaptureButton.setDisable(true);
        importProgressBar.setProgress(0);
        applyRuleSettings(initialRuleSettings);
        refreshInterfacesAsync();
        if (persistence == null) {
            databaseStatusLabel.setText("DATABASE UNAVAILABLE");
            databaseStatusLabel.setTooltip(new Tooltip(
                    Optional.ofNullable(persistenceFailure).orElse("Persistent storage could not be initialized.")));
            importStatusLabel.setText("Database unavailable; PCAP imports are disabled to prevent data loss.");
            interfaceHelpLabel.setText("Capture requires persistent storage; configure MySQL before monitoring.");
            updateCaptureControls();
            return;
        }
        databaseStatusLabel.setText("DATABASE READY");
        databaseStatusLabel.setTooltip(new Tooltip(persistence.storageDescription()));
        loadDashboardAsync();
    }

    @FXML
    private void handleRefreshInterfaces() {
        refreshInterfacesAsync();
    }

    private void refreshInterfacesAsync() {
        if (closed) {
            return;
        }
        refreshInterfacesButton.setDisable(true);
        captureInterfaceCombo.getItems().clear();
        interfaceHelpLabel.setText("Looking for available capture interfaces...");
        Task<List<LiveCaptureInterface>> task = new Task<>() {
            @Override
            protected List<LiveCaptureInterface> call() throws Exception {
                return livePacketSource.listInterfaces();
            }
        };
        task.setOnSucceeded(event -> {
            if (closed) {
                return;
            }
            captureInterfaceCombo.setItems(FXCollections.observableArrayList(task.getValue()));
            if (task.getValue().isEmpty()) {
                interfaceHelpLabel.setText(
                        "No capture interfaces were reported. Verify Npcap installation and interface availability.");
            } else {
                captureInterfaceCombo.getSelectionModel().selectFirst();
                interfaceHelpLabel.setText(
                        "Passive, non-promiscuous capture sees only traffic delivered to this adapter.");
            }
            updateCaptureControls();
        });
        task.setOnFailed(event -> {
            if (closed) {
                return;
            }
            Throwable failure = task.getException();
            String message = failure == null ? "Unknown interface enumeration error" : failure.getMessage();
            interfaceHelpLabel.setText("Unable to enumerate interfaces: " + message);
            LOGGER.error("Unable to enumerate live capture interfaces", failure);
            updateCaptureControls();
        });
        task.setOnCancelled(event -> {
            if (!closed) {
                interfaceHelpLabel.setText("Interface enumeration was cancelled.");
                updateCaptureControls();
            }
        });
        captureControlExecutor.execute(task);
    }

    @FXML
    private void handleStartCapture() {
        if (closed || !persistenceReady || liveCaptureService == null
                || activeImport != null || captureInterfaceCombo.getValue() == null) {
            return;
        }
        DetectionRuleSettings ruleSettings = readRuleSettings();
        if (ruleSettings == null) {
            return;
        }
        String interfaceName = captureInterfaceCombo.getValue().name();
        if (!liveCaptureService.start(interfaceName, ruleSettings)) {
            return;
        }
        importHistoryTable.getSelectionModel().clearSelection();
        traffic.clear();
        observedEndpoints.clear();
        importStatusLabel.setText("Starting passive live capture on " + interfaceName + "...");
        setControlsBusy(false);
    }

    @FXML
    private void handleStopCapture() {
        if (liveCaptureService != null) {
            liveCaptureService.stop();
            captureStatusLabel.setText("CAPTURE STOPPING");
            setControlsBusy(activeImport != null);
        }
    }

    private void applyLiveCaptureSnapshot(LiveCaptureSnapshot snapshot) {
        LiveCaptureState previousState = lastCaptureState;
        lastCaptureState = snapshot.state();
        String interfaceText = snapshot.interfaceName().orElse("no interface");
        captureStatusLabel.setText("CAPTURE " + snapshot.state().name());
        captureStatusBarLabel.setText(snapshot.state().name());
        captureMetricsLabel.setText(String.format(
                "%,d packets · %s · %.1f pkt/s · %s/s · %,d tracked flow tuples",
                snapshot.packetsCaptured(),
                formatBytes(snapshot.bytesCaptured()),
                snapshot.packetsPerSecond(),
                formatBytes((long) snapshot.bytesPerSecond()),
                snapshot.trackedFlowTuples()));
        sourceStatusLabel.setText(switch (snapshot.state()) {
            case STARTING -> "CAPTURE STARTING";
            case RUNNING -> "CAPTURE RUNNING";
            case STOPPING -> "CAPTURE STOPPING";
            case STOPPED -> "CAPTURE STOPPED";
            case FAILED -> "CAPTURE FAILED";
            case IDLE -> "SOURCE NOT CONNECTED";
        });
        engineStatusLabel.setText(snapshot.state() == LiveCaptureState.RUNNING
                ? "ENGINE RUNNING" : "ENGINE IDLE");

        if (snapshot.state() == LiveCaptureState.RUNNING
                || snapshot.state() == LiveCaptureState.STOPPING) {
            traffic.setAll(snapshot.recentTraffic());
            alerts.setAll(snapshot.recentAlerts());
            observedEndpoints.setAll(snapshot.observedEndpoints());
            packetsValue.setText(Long.toString(snapshot.packetsCaptured()));
            sourceIpsValue.setText(Integer.toString(snapshot.observedEndpoints().size()));
            alertsValue.setText(Long.toString(snapshot.alertsGenerated()));
            importStatusLabel.setText(
                    "Monitoring " + interfaceText + " · parsed " + snapshot.packetsParsed()
                            + " · unsupported " + snapshot.unsupportedPackets()
                            + " · malformed " + snapshot.malformedPackets()
                            + " · alerts retained " + snapshot.recentAlerts().size());
        } else if (snapshot.state() == LiveCaptureState.STOPPED) {
            importStatusLabel.setText(
                    "Live capture stopped and persisted: " + snapshot.packetsCaptured() + " packets, "
                            + snapshot.packetsParsed() + " parsed, " + snapshot.alertsGenerated()
                            + " findings generated for " + interfaceText + ".");
        }
        if (snapshot.failureMessage().isPresent()) {
            String failure = snapshot.failureMessage().orElseThrow();
            importStatusLabel.setText("Live monitoring failed: " + failure);
            if (failure.startsWith("Persistent storage failed:")) {
                databaseStatusLabel.setText("DATABASE ERROR");
                persistenceReady = false;
            }
        }
        if (snapshot.alertsOmitted() > 0) {
            importStatusLabel.setText(importStatusLabel.getText()
                    + " " + snapshot.alertsOmitted() + " alerts were omitted by the 2,000-alert session limit.");
        }
        setControlsBusy(activeImport != null);
        if ((snapshot.state() == LiveCaptureState.STOPPED
                || snapshot.state() == LiveCaptureState.FAILED)
                && previousState != snapshot.state()) {
            refreshDashboardAsync();
        }
    }

    @FXML
    private void handleChooseFile() {
        if (!persistenceReady || closed
                || liveCaptureService != null && isCaptureActive(liveCaptureService.snapshot().state())) {
            return;
        }
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
        if (closed || !persistenceReady || selectedFile == null || activeImport != null
                || liveCaptureService != null && isCaptureActive(liveCaptureService.snapshot().state())) {
            return;
        }
        DetectionRuleSettings ruleSettings = readRuleSettings();
        if (ruleSettings == null) {
            return;
        }
        Path importPath = selectedFile;
        UUID importId = UUID.randomUUID();
        importCancellation = new AtomicBoolean();
        Task<ImportTaskResult> task = new Task<>() {
            @Override
            protected ImportTaskResult call() throws Exception {
                persistence.saveRuleSettings(ruleSettings);
                updateMessage("Creating import history and validating PCAP header...");
                ImportSummary summary = importService.importFile(
                        importPath,
                        importId,
                        ruleSettings,
                        importCancellation::get,
                        (bytesRead, fileSize, packetCount) -> {
                            updateProgress(bytesRead, fileSize);
                            updateMessage("Reading packet " + packetCount + " · " + formatBytes(bytesRead)
                                    + " of " + formatBytes(fileSize));
                        });
                return new ImportTaskResult(summary);
            }
        };
        activeImport = task;
        setControlsBusy(true);
        importStatusLabel.textProperty().unbind();
        importStatusLabel.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(event -> {
            if (closed) {
                return;
            }
            importStatusLabel.textProperty().unbind();
            importProgressBar.progressProperty().unbind();
            ImportSummary result = task.getValue().summary();
            importHistoryTable.getSelectionModel().clearSelection();
            traffic.setAll(result.trafficSample());
            packetsValue.setText(Long.toString(result.packetsParsed()));
            sourceIpsValue.setText(Integer.toString(result.trackedSources()));
            sourceStatusLabel.setText("SOURCE IMPORTED");
            engineStatusLabel.setText("ENGINE READY");
            importStatusLabel.setText("Completed and persisted: " + result.packetsRead() + " records, "
                    + result.packetsParsed() + " parsed, " + result.unsupportedPackets()
                    + " unsupported, " + result.malformedPackets() + " malformed, "
                    + result.alertsGenerated() + " alerts generated, "
                    + result.latePacketsDropped() + " late packets excluded.");
            if (result.aggregationCapacityDroppedPackets() > 0) {
                importStatusLabel.setText(importStatusLabel.getText()
                        + " " + result.aggregationCapacityDroppedPackets()
                        + " packets excluded by aggregation capacity ("
                        + result.aggregationEvictedSources() + " sources, "
                        + result.aggregationEvictedBuckets() + " time buckets evicted).");
            }
            if (result.alertsOmittedByImportLimit() > 0) {
                importStatusLabel.setText(importStatusLabel.getText()
                        + " " + result.alertsOmittedByImportLimit()
                        + " alerts omitted by the per-import alert limit.");
            }
            importProgressBar.setProgress(1);
            activeImport = null;
            importCancellation = null;
            setControlsBusy(false);
            refreshDashboardAsync();
        });
        task.setOnCancelled(event -> {
            if (closed) {
                return;
            }
            importStatusLabel.textProperty().unbind();
            importProgressBar.progressProperty().unbind();
            importProgressBar.setProgress(0);
            importStatusLabel.setText("Import cancelled. Partial alerts were not persisted.");
            activeImport = null;
            importCancellation = null;
            setControlsBusy(false);
            refreshDashboardAsync();
        });
        task.setOnFailed(event -> {
            if (closed) {
                return;
            }
            importStatusLabel.textProperty().unbind();
            importProgressBar.progressProperty().unbind();
            importProgressBar.setProgress(0);
            Throwable failure = task.getException();
            String message = failure == null ? "Unknown import error" : failure.getMessage();
            if (failure instanceof CancellationException) {
                importStatusLabel.setText("Import cancelled; processed records and cancellation status were saved.");
            } else {
                importStatusLabel.setText("Import failed; persistence was not confirmed: " + message);
            }
            if (failure instanceof CancellationException) {
                LOGGER.info("PCAP import cancelled for '{}'", importPath.getFileName());
            } else {
                LOGGER.error("PCAP import task failed for '{}': {}",
                        importPath.getFileName(), message, failure);
            }
            activeImport = null;
            importCancellation = null;
            setControlsBusy(false);
            if (failure instanceof PersistenceException) {
                handleDatabaseUnavailable(failure);
                return;
            }
            refreshDashboardAsync();
        });
        importProgressBar.progressProperty().unbind();
        importProgressBar.progressProperty().bind(task.progressProperty());
        importExecutor.execute(task);
    }

    @FXML
    private void handleSaveRules() {
        if (closed || !persistenceReady
                || liveCaptureService != null && isCaptureActive(liveCaptureService.snapshot().state())) {
            return;
        }
        DetectionRuleSettings ruleSettings = readRuleSettings();
        if (ruleSettings == null) {
            return;
        }
        Task<Void> task = new Task<>() {
            @Override
            protected Void call() {
                persistence.saveRuleSettings(ruleSettings);
                return null;
            }
        };
        setControlsBusy(true);
        task.setOnSucceeded(event -> {
            if (closed) {
                return;
            }
            importStatusLabel.setText("Detection rule configuration saved.");
            setControlsBusy(false);
        });
        task.setOnFailed(event -> {
            if (closed) {
                return;
            }
            Throwable failure = task.getException();
            importStatusLabel.setText("Unable to save detection rules: "
                    + (failure == null ? "Unknown persistence error" : failure.getMessage()));
            LOGGER.error("Unable to persist detection rule configuration", failure);
            setControlsBusy(false);
            if (failure instanceof PersistenceException) {
                handleDatabaseUnavailable(failure);
            }
        });
        importExecutor.execute(task);
    }

    @FXML
    private void handleShowRecentAlerts() {
        if (closed || !persistenceReady) {
            return;
        }
        importHistoryTable.getSelectionModel().clearSelection();
        loadLatestAlertsAsync();
    }

    private DetectionRuleSettings readRuleSettings() {
        try {
            return new DetectionRuleSettings(
                    parseThreshold(portScanThreshold, "Port scan"),
                    parseThreshold(synThreshold, "SYN"),
                    parseThreshold(icmpThreshold, "ICMP"),
                    parseThreshold(observationWindow, "Observation window"),
                    portScanEnabled.isSelected(),
                    synEnabled.isSelected(),
                    icmpEnabled.isSelected());
        } catch (IllegalArgumentException exception) {
            importStatusLabel.setText("Rule configuration error: " + exception.getMessage());
            return null;
        }
    }

    @FXML
    private void handleCancelImport() {
        if (activeImport != null && importCancellation != null) {
            importCancellation.set(true);
            cancelImportButton.setDisable(true);
            importStatusLabel.textProperty().unbind();
            importStatusLabel.setText("Cancelling import...");
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
        detail.setHeaderText(selected.ruleName() + " (" + selected.ruleId() + ") · " + selected.severity());
        detail.setContentText(selected.description() + "\n\n" + selected.evidence()
                + "\n\nStatus: " + AlertStatus.NEW
                + "\nImport ID: " + selected.importId());
        detail.showAndWait();
    }

    public void shutdown() {
        if (closed) {
            return;
        }
        closed = true;
        if (importCancellation != null) {
            importCancellation.set(true);
        }
        importStatusLabel.textProperty().unbind();
        importProgressBar.progressProperty().unbind();
        if (liveCaptureService != null) {
            liveCaptureService.close();
        }
        captureControlExecutor.shutdownNow();
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

    private void setControlsBusy(boolean busy) {
        boolean captureActive = liveCaptureService != null
                && isCaptureActive(liveCaptureService.snapshot().state());
        chooseFileButton.setDisable(busy || captureActive || !persistenceReady);
        startImportButton.setDisable(
                busy || captureActive || !persistenceReady || selectedFile == null);
        saveRulesButton.setDisable(busy || captureActive || !persistenceReady);
        cancelImportButton.setDisable(activeImport == null
                || importCancellation != null && importCancellation.get());
        boolean ruleControlsDisabled = busy || captureActive;
        portScanEnabled.setDisable(ruleControlsDisabled);
        synEnabled.setDisable(ruleControlsDisabled);
        icmpEnabled.setDisable(ruleControlsDisabled);
        portScanThreshold.setDisable(ruleControlsDisabled);
        synThreshold.setDisable(ruleControlsDisabled);
        icmpThreshold.setDisable(ruleControlsDisabled);
        observationWindow.setDisable(ruleControlsDisabled);
        updateCaptureControls();
    }

    private void updateCaptureControls() {
        if (captureInterfaceCombo == null || startCaptureButton == null) {
            return;
        }
        LiveCaptureState state = liveCaptureService == null
                ? LiveCaptureState.IDLE : liveCaptureService.snapshot().state();
        boolean active = isCaptureActive(state);
        boolean busy = activeImport != null;
        boolean noInterface = captureInterfaceCombo.getValue() == null;
        captureInterfaceCombo.setDisable(active || busy);
        refreshInterfacesButton.setDisable(active || busy);
        startCaptureButton.setDisable(
                closed || !persistenceReady || busy || active || noInterface);
        stopCaptureButton.setDisable(
                closed || state != LiveCaptureState.RUNNING && state != LiveCaptureState.STARTING);
    }

    private static boolean isCaptureActive(LiveCaptureState state) {
        return state == LiveCaptureState.STARTING
                || state == LiveCaptureState.RUNNING
                || state == LiveCaptureState.STOPPING;
    }

    private void applyRuleSettings(DetectionRuleSettings settings) {
        portScanThreshold.setText(Long.toString(settings.portScanThreshold()));
        synThreshold.setText(Long.toString(settings.synThreshold()));
        icmpThreshold.setText(Long.toString(settings.icmpThreshold()));
        observationWindow.setText(Long.toString(settings.observationWindowSeconds()));
        portScanEnabled.setSelected(settings.portScanEnabled());
        synEnabled.setSelected(settings.synEnabled());
        icmpEnabled.setSelected(settings.icmpEnabled());
    }

    private void loadDashboardAsync() {
        Task<DashboardSnapshot> task = new Task<>() {
            @Override
            protected DashboardSnapshot call() {
                return loadDashboardState();
            }
        };
        task.setOnSucceeded(event -> {
            if (closed) {
                return;
            }
            applyDashboardState(task.getValue());
            persistenceReady = true;
            databaseStatusLabel.setText("DATABASE READY");
            importStatusLabel.setText("Persistent alert and import history loaded.");
            setControlsBusy(false);
        });
        task.setOnFailed(event -> handleDatabaseUnavailable(task.getException()));
        importExecutor.execute(task);
    }

    private void refreshDashboardAsync() {
        if (closed || persistence == null) {
            return;
        }
        Task<DashboardSnapshot> task = new Task<>() {
            @Override
            protected DashboardSnapshot call() {
                return loadDashboardState();
            }
        };
        task.setOnSucceeded(event -> {
            if (!closed) {
                applyDashboardState(task.getValue());
            }
        });
        task.setOnFailed(event -> {
            if (!closed) {
                handleDatabaseUnavailable(task.getException());
            }
        });
        importExecutor.execute(task);
    }

    private DashboardSnapshot loadDashboardState() {
        return new DashboardSnapshot(
                persistence.findRecent(500),
                persistence.recentImports(100),
                persistence.countAlerts(),
                persistence.countCriticalAlerts());
    }

    private void applyDashboardState(DashboardSnapshot state) {
        alerts.setAll(state.alerts());
        importHistory.setAll(state.imports());
        alertsValue.setText(Long.toString(state.alertCount()));
        criticalAlertsValue.setText(Long.toString(state.criticalAlertCount()));
    }

    private void showImportAlerts(UUID importId) {
        if (closed || !persistenceReady) {
            return;
        }
        Task<List<IntrusionAlert>> task = new Task<>() {
            @Override
            protected List<IntrusionAlert> call() {
                return persistence.findByImport(importId, 500);
            }
        };
        task.setOnSucceeded(event -> {
            if (closed) {
                return;
            }
            ImportSession selected = importHistoryTable.getSelectionModel().getSelectedItem();
            if (selected != null && selected.id().equals(importId)) {
                alerts.setAll(task.getValue());
            }
        });
        task.setOnFailed(event -> {
            if (!closed) {
                Throwable failure = task.getException();
                importStatusLabel.setText("Unable to load alerts for this import: "
                        + (failure == null ? "Unknown database error" : failure.getMessage()));
                LOGGER.error("Unable to load alerts for import {}", importId, failure);
            }
        });
        importExecutor.execute(task);
    }

    private void loadLatestAlertsAsync() {
        Task<List<IntrusionAlert>> task = new Task<>() {
            @Override
            protected List<IntrusionAlert> call() {
                return persistence.findRecent(500);
            }
        };
        task.setOnSucceeded(event -> {
            if (!closed) {
                alerts.setAll(task.getValue());
            }
        });
        task.setOnFailed(event -> {
            if (!closed) {
                Throwable failure = task.getException();
                importStatusLabel.setText("Unable to load recent alerts: "
                        + (failure == null ? "Unknown database error" : failure.getMessage()));
                LOGGER.error("Unable to load recent persisted alerts", failure);
            }
        });
        importExecutor.execute(task);
    }

    private void handleDatabaseUnavailable(Throwable failure) {
        if (closed) {
            return;
        }
        persistenceReady = false;
        String message = failure == null ? "Unknown database error" : failure.getMessage();
        databaseStatusLabel.setText("DATABASE ERROR");
        importStatusLabel.setText("Persistent storage unavailable; imports are disabled: " + message);
        LOGGER.error("Persistent storage became unavailable", failure);
        setControlsBusy(false);
    }

    private record DashboardSnapshot(
            List<IntrusionAlert> alerts,
            List<ImportSession> imports,
            long alertCount,
            long criticalAlertCount) {
    }

    private record ImportTaskResult(ImportSummary summary) {
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
