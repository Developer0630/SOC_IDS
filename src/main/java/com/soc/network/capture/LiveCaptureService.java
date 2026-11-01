package com.soc.network.capture;

import com.soc.detection.DetectionEngine;
import com.soc.detection.DetectionRuleSettings;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.model.ObservedEndpoint;
import com.soc.persistence.ImportPersistence;
import com.soc.persistence.ImportSession;
import com.soc.persistence.ImportSessionStatus;
import com.soc.persistence.PersistenceException;
import com.soc.network.parser.PacketParseResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class LiveCaptureService implements AutoCloseable {
    private static final Logger LOGGER = LoggerFactory.getLogger(LiveCaptureService.class);
    private static final int TRAFFIC_SAMPLE_LIMIT = 500;
    private static final int ALERTS_PER_SESSION_LIMIT = 2_000;
    private static final int FLOW_TRACKING_LIMIT = 10_000;
    private static final int ENDPOINT_TRACKING_LIMIT = 1_000;
    private static final long RATE_UPDATE_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final ImportPersistence persistence;
    private final LivePacketSource packetSource;
    private final LiveCaptureListener listener;
    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "sentinel-live-capture");
        thread.setDaemon(true);
        return thread;
    });
    private final ScheduledExecutorService snapshotExecutor = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "sentinel-live-capture-status");
        thread.setDaemon(true);
        return thread;
    });
    private final ArrayDeque<NetworkPacket> recentTraffic = new ArrayDeque<>(TRAFFIC_SAMPLE_LIMIT);
    private final ArrayDeque<IntrusionAlert> recentAlerts = new ArrayDeque<>(TRAFFIC_SAMPLE_LIMIT);
    private final List<IntrusionAlert> alertsForPersistence = new ArrayList<>(ALERTS_PER_SESSION_LIMIT);
    private final LinkedHashSet<FlowTuple> flowTuples = new LinkedHashSet<>();
    private final LinkedHashMap<String, MutableEndpoint> endpoints = new LinkedHashMap<>();

    private LiveCaptureState state = LiveCaptureState.IDLE;
    private Optional<String> interfaceName = Optional.empty();
    private Optional<String> failureMessage = Optional.empty();
    private AtomicBoolean stopRequested;
    private LiveCaptureHandle activeHandle;
    private ImportSession runningSession;
    private DetectionEngine detectionEngine;
    private long packetsCaptured;
    private long bytesCaptured;
    private long packetsParsed;
    private long unsupportedPackets;
    private long malformedPackets;
    private long alertsGenerated;
    private long alertsOmitted;
    private long lastRatePacketCount;
    private long lastRateByteCount;
    private long lastRateUpdateNanos = System.nanoTime();
    private double packetsPerSecond;
    private double bytesPerSecond;
    private boolean closed;

    public LiveCaptureService(
            ImportPersistence persistence,
            LiveCaptureListener listener) {
        this(persistence, new Pcap4jLivePacketSource(), listener);
    }

    public LiveCaptureService(
            ImportPersistence persistence,
            LivePacketSource packetSource,
            LiveCaptureListener listener) {
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        this.packetSource = Objects.requireNonNull(packetSource, "packetSource");
        this.listener = Objects.requireNonNull(listener, "listener");
        snapshotExecutor.scheduleAtFixedRate(
                this::publishSnapshotSafely, 0, 1, TimeUnit.SECONDS);
    }

    public List<LiveCaptureInterface> listInterfaces() throws IOException {
        return packetSource.listInterfaces();
    }

    public synchronized LiveCaptureSnapshot snapshot() {
        updateRates();
        return snapshotLocked();
    }

    public boolean start(String selectedInterface, DetectionRuleSettings ruleSettings) {
        Objects.requireNonNull(ruleSettings, "ruleSettings");
        if (selectedInterface == null || selectedInterface.isBlank()) {
            throw new IllegalArgumentException("Select a network interface before starting capture");
        }
        synchronized (this) {
            if (closed || isActive(state)) {
                return false;
            }
            resetForSession(selectedInterface);
            state = LiveCaptureState.STARTING;
            stopRequested = new AtomicBoolean();
            publishSnapshotLocked();
        }
        try {
            captureExecutor.execute(() -> capture(selectedInterface, ruleSettings));
            return true;
        } catch (RuntimeException exception) {
            failBeforeSession("Unable to start capture worker: " + exception.getMessage(), exception);
            return false;
        }
    }

    public void stop() {
        LiveCaptureHandle handleToStop;
        synchronized (this) {
            if (!isActive(state)) {
                return;
            }
            stopRequested.set(true);
            state = LiveCaptureState.STOPPING;
            handleToStop = activeHandle;
            publishSnapshotLocked();
        }
        if (handleToStop != null) {
            handleToStop.stop();
        }
    }

    private void capture(String selectedInterface, DetectionRuleSettings ruleSettings) {
        LiveCaptureHandle captureHandle = null;
        ImportSession session = null;
        try {
            persistence.saveRuleSettings(ruleSettings);
            UUID sessionId = UUID.randomUUID();
            session = ImportSession.running(
                    sessionId, "LIVE: " + selectedInterface, Instant.now());
            persistence.startImport(session);
            synchronized (this) {
                runningSession = session;
                detectionEngine = DetectionEngine.defaults(sessionId, ruleSettings);
            }

            captureHandle = packetSource.open(selectedInterface, this::acceptPacket);
            synchronized (this) {
                activeHandle = captureHandle;
                if (stopRequested.get()) {
                    captureHandle.stop();
                } else {
                    state = LiveCaptureState.RUNNING;
                }
                publishSnapshotLocked();
            }
            captureHandle.loop();
            if (!stopRequested.get()) {
                throw new IOException("Capture ended unexpectedly; the selected interface may have disconnected.");
            }

            ImportSession completed = finishSession(session, ImportSessionStatus.COMPLETED, Optional.empty());
            persistence.completeImport(completed, alertsForPersistenceSnapshot());
            synchronized (this) {
                runningSession = null;
                state = LiveCaptureState.STOPPED;
                publishSnapshotLocked();
            }
            LOGGER.info(
                    "Live capture stopped and persisted: interface='{}', packets={}, parsed={}, alerts={}, omitted={}",
                    selectedInterface, packetCount(), parsedCount(), generatedAlertCount(), omittedAlertCount());
        } catch (Exception exception) {
            if (session != null) {
                recordFailedSession(session, exception);
            }
            String message = messageFor(exception);
            LOGGER.error("Live capture failed on interface '{}': {}", selectedInterface, message, exception);
            synchronized (this) {
                runningSession = null;
                failureMessage = Optional.of(message);
                state = LiveCaptureState.FAILED;
                publishSnapshotLocked();
            }
        } finally {
            if (captureHandle != null) {
                captureHandle.close();
            }
            synchronized (this) {
                if (activeHandle == captureHandle) {
                    activeHandle = null;
                }
            }
        }
    }

    private void acceptPacket(LiveCapturedPacket captured) {
        synchronized (this) {
            if (state == LiveCaptureState.FAILED || closed) {
                return;
            }
            packetsCaptured++;
            bytesCaptured = Math.addExact(bytesCaptured, captured.originalLength());
            PacketParseResult result = captured.parseResult();
            if (result.status() == PacketParseResult.Status.UNSUPPORTED) {
                unsupportedPackets++;
                return;
            }
            if (result.status() == PacketParseResult.Status.MALFORMED) {
                malformedPackets++;
                return;
            }
            NetworkPacket packet = result.packet().orElseThrow();
            packetsParsed++;
            addRecent(recentTraffic, packet, TRAFFIC_SAMPLE_LIMIT);
            addEndpoints(packet);
            addFlow(packet);
            for (IntrusionAlert alert : detectionEngine.process(packet)) {
                alertsGenerated++;
                addRecent(recentAlerts, alert, TRAFFIC_SAMPLE_LIMIT);
                if (alertsForPersistence.size() < ALERTS_PER_SESSION_LIMIT) {
                    alertsForPersistence.add(alert);
                } else {
                    alertsOmitted++;
                }
            }
        }
    }

    private void addEndpoints(NetworkPacket packet) {
        packet.sourceAddress().ifPresent(address ->
                recordEndpoint(address, packet.sourceMac(), packet.timestamp()));
        packet.destinationAddress().ifPresent(address ->
                recordEndpoint(address, Optional.empty(), packet.timestamp()));
    }

    private void recordEndpoint(String address, Optional<String> macAddress, Instant timestamp) {
        String key = address + "\u0000" + macAddress.orElse("");
        MutableEndpoint endpoint = endpoints.get(key);
        if (endpoint == null) {
            if (endpoints.size() >= ENDPOINT_TRACKING_LIMIT) {
                String oldestKey = endpoints.keySet().iterator().next();
                endpoints.remove(oldestKey);
            }
            endpoints.put(key, new MutableEndpoint(address, macAddress, timestamp));
            return;
        }
        endpoint.record(timestamp);
    }

    private void addFlow(NetworkPacket packet) {
        if (packet.sourceAddress().isEmpty() || packet.destinationAddress().isEmpty()) {
            return;
        }
        FlowTuple tuple = new FlowTuple(
                packet.sourceAddress().orElseThrow(),
                packet.sourcePort().orElse(-1),
                packet.destinationAddress().orElseThrow(),
                packet.destinationPort().orElse(-1),
                packet.protocol().name());
        if (!flowTuples.contains(tuple) && flowTuples.size() == FLOW_TRACKING_LIMIT) {
            flowTuples.remove(flowTuples.iterator().next());
        }
        flowTuples.add(tuple);
    }

    private ImportSession finishSession(
            ImportSession session,
            ImportSessionStatus finalStatus,
            Optional<String> error) {
        synchronized (this) {
            return session.finish(
                    finalStatus,
                    Instant.now(),
                    packetsCaptured,
                    packetsParsed,
                    unsupportedPackets,
                    malformedPackets,
                    alertsGenerated,
                    error);
        }
    }

    private void recordFailedSession(ImportSession session, Exception originalFailure) {
        try {
            persistence.finishImport(finishSession(
                    session,
                    ImportSessionStatus.FAILED,
                    Optional.of(messageFor(originalFailure))));
        } catch (RuntimeException persistenceFailure) {
            originalFailure.addSuppressed(persistenceFailure);
            LOGGER.error("Unable to persist terminal state for live session {}", session.id(), persistenceFailure);
        }
    }

    private List<IntrusionAlert> alertsForPersistenceSnapshot() {
        synchronized (this) {
            return List.copyOf(alertsForPersistence);
        }
    }

    private void failBeforeSession(String message, RuntimeException exception) {
        LOGGER.error(message, exception);
        synchronized (this) {
            failureMessage = Optional.of(message);
            state = LiveCaptureState.FAILED;
            publishSnapshotLocked();
        }
    }

    private synchronized long packetCount() {
        return packetsCaptured;
    }

    private synchronized long parsedCount() {
        return packetsParsed;
    }

    private synchronized long generatedAlertCount() {
        return alertsGenerated;
    }

    private synchronized long omittedAlertCount() {
        return alertsOmitted;
    }

    private void resetForSession(String selectedInterface) {
        interfaceName = Optional.of(selectedInterface);
        failureMessage = Optional.empty();
        runningSession = null;
        detectionEngine = null;
        recentTraffic.clear();
        recentAlerts.clear();
        alertsForPersistence.clear();
        flowTuples.clear();
        endpoints.clear();
        packetsCaptured = 0;
        bytesCaptured = 0;
        packetsParsed = 0;
        unsupportedPackets = 0;
        malformedPackets = 0;
        alertsGenerated = 0;
        alertsOmitted = 0;
        packetsPerSecond = 0;
        bytesPerSecond = 0;
        lastRatePacketCount = 0;
        lastRateByteCount = 0;
        lastRateUpdateNanos = System.nanoTime();
    }

    private void updateRates() {
        long now = System.nanoTime();
        long elapsed = now - lastRateUpdateNanos;
        if (elapsed < RATE_UPDATE_NANOS) {
            return;
        }
        double seconds = elapsed / 1_000_000_000.0;
        packetsPerSecond = (packetsCaptured - lastRatePacketCount) / seconds;
        bytesPerSecond = (bytesCaptured - lastRateByteCount) / seconds;
        lastRatePacketCount = packetsCaptured;
        lastRateByteCount = bytesCaptured;
        lastRateUpdateNanos = now;
    }

    private synchronized void publishSnapshotSafely() {
        if (!closed) {
            publishSnapshotLocked();
        }
    }

    private void publishSnapshotLocked() {
        LiveCaptureSnapshot snapshot = snapshotLocked();
        try {
            listener.onSnapshot(snapshot);
        } catch (RuntimeException exception) {
            LOGGER.error("Live capture status listener failed", exception);
        }
    }

    private LiveCaptureSnapshot snapshotLocked() {
        updateRates();
        List<ObservedEndpoint> observed = endpoints.values().stream()
                .map(MutableEndpoint::snapshot)
                .sorted(Comparator.comparingLong(ObservedEndpoint::packetsSeen).reversed())
                .toList();
        return new LiveCaptureSnapshot(
                state,
                interfaceName,
                packetsCaptured,
                bytesCaptured,
                packetsParsed,
                unsupportedPackets,
                malformedPackets,
                alertsGenerated,
                alertsOmitted,
                flowTuples.size(),
                packetsPerSecond,
                bytesPerSecond,
                List.copyOf(recentTraffic),
                List.copyOf(recentAlerts),
                observed,
                failureMessage);
    }

    private static boolean isActive(LiveCaptureState state) {
        return state == LiveCaptureState.STARTING
                || state == LiveCaptureState.RUNNING
                || state == LiveCaptureState.STOPPING;
    }

    private static String messageFor(Exception exception) {
        String message = exception.getMessage();
        if (exception instanceof PersistenceException) {
            return "Persistent storage failed: " + Objects.requireNonNullElse(message, "unknown database error");
        }
        return Objects.requireNonNullElse(message, exception.getClass().getSimpleName());
    }

    private static <T> void addRecent(ArrayDeque<T> values, T value, int limit) {
        if (values.size() == limit) {
            values.removeFirst();
        }
        values.addLast(value);
    }

    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
        }
        stop();
        snapshotExecutor.shutdownNow();
        captureExecutor.shutdown();
    }

    private record FlowTuple(
            String source,
            int sourcePort,
            String destination,
            int destinationPort,
            String protocol) {
    }

    private static final class MutableEndpoint {
        private final String address;
        private final Optional<String> macAddress;
        private Instant firstSeen;
        private Instant lastSeen;
        private long packetsSeen = 1;

        private MutableEndpoint(String address, Optional<String> macAddress, Instant timestamp) {
            this.address = address;
            this.macAddress = macAddress;
            this.firstSeen = timestamp;
            this.lastSeen = timestamp;
        }

        private void record(Instant timestamp) {
            packetsSeen++;
            if (timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }
        }

        private ObservedEndpoint snapshot() {
            return new ObservedEndpoint(address, macAddress, packetsSeen, firstSeen, lastSeen);
        }
    }
}
