package com.soc.network.capture;

import com.soc.detection.DetectionEngine;
import com.soc.detection.DetectionRuleSettings;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.persistence.ImportPersistence;
import com.soc.persistence.ImportSession;
import com.soc.persistence.ImportSessionStatus;
import com.soc.persistence.PersistenceException;
import com.soc.network.parser.PacketParseResult;
import com.soc.network.parser.PcapPacketParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class PcapImportService {
    private static final Logger LOGGER = LoggerFactory.getLogger(PcapImportService.class);
    private static final int TRAFFIC_SAMPLE_LIMIT = 500;
    private static final int ALERTS_PER_IMPORT_LIMIT = 2000;

    private final PcapReadConfig readConfig;
    private final ImportPersistence persistence;
    private final PcapFileReader reader;
    private final PcapPacketParser parser;

    public PcapImportService(PcapReadConfig readConfig, ImportPersistence persistence) {
        this(readConfig, persistence, new PcapFileReader(), new PcapPacketParser());
    }

    PcapImportService(
            PcapReadConfig readConfig,
            ImportPersistence persistence,
            PcapFileReader reader,
            PcapPacketParser parser) {
        this.readConfig = Objects.requireNonNull(readConfig, "readConfig");
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        this.reader = Objects.requireNonNull(reader, "reader");
        this.parser = Objects.requireNonNull(parser, "parser");
    }

    public ImportSummary importFile(
            Path file,
            UUID importId,
            BooleanSupplier cancelled,
            PcapFileReader.ProgressListener progress) throws IOException {
        return importFile(file, importId, DetectionRuleSettings.defaults(), cancelled, progress);
    }

    public ImportSummary importFile(
            Path file,
            UUID importId,
            DetectionRuleSettings ruleSettings,
            BooleanSupplier cancelled,
            PcapFileReader.ProgressListener progress) throws IOException {
        Objects.requireNonNull(importId, "importId");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(ruleSettings, "ruleSettings");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(progress, "progress");

        Instant startedAt = Instant.now();
        ImportSession runningSession = ImportSession.running(
                importId, file.getFileName().toString(), startedAt);
        persistence.startImport(runningSession);
        DetectionEngine detectionEngine = DetectionEngine.defaults(importId, ruleSettings);
        ArrayDeque<NetworkPacket> traffic = new ArrayDeque<>(TRAFFIC_SAMPLE_LIMIT);
        List<IntrusionAlert> alerts = new ArrayList<>();
        long[] counters = new long[5];

        try {
            reader.read(file, readConfig, cancelled, record -> {
                if (cancelled.getAsBoolean()) {
                    throw new CancellationException("PCAP import cancelled");
                }
                counters[0]++;
                PacketParseResult parseResult = parser.parse(record);
                switch (parseResult.status()) {
                    case UNSUPPORTED -> counters[2]++;
                    case MALFORMED -> counters[3]++;
                    case PARSED -> {
                        NetworkPacket packet = parseResult.packet().orElseThrow();
                        counters[1]++;
                        if (traffic.size() == TRAFFIC_SAMPLE_LIMIT) {
                            traffic.removeFirst();
                        }
                        traffic.addLast(packet);
                        List<IntrusionAlert> findings = detectionEngine.process(packet);
                        counters[4] += findings.size();
                        for (IntrusionAlert alert : findings) {
                            if (alerts.size() < ALERTS_PER_IMPORT_LIMIT) {
                                alerts.add(alert);
                            }
                        }
                    }
                }
            }, progress);
            if (cancelled.getAsBoolean()) {
                throw new CancellationException("PCAP import cancelled");
            }
        } catch (IOException | RuntimeException exception) {
            ImportSessionStatus status = exception instanceof CancellationException
                    ? ImportSessionStatus.CANCELLED
                    : ImportSessionStatus.FAILED;
            ImportSession terminalSession = runningSession.finish(
                    status, Instant.now(), counters[0], counters[1], counters[2], counters[3],
                    counters[4], Optional.ofNullable(exception.getMessage()));
            try {
                persistence.finishImport(terminalSession);
            } catch (RuntimeException persistenceFailure) {
                exception.addSuppressed(persistenceFailure);
                LOGGER.error("Unable to record terminal status for import {}", importId, persistenceFailure);
                if (exception instanceof CancellationException) {
                    throw new PersistenceException(
                            "Import was cancelled but its terminal status could not be persisted",
                            exception);
                }
            }
            if (!(exception instanceof CancellationException)) {
                LOGGER.error("PCAP import failed for '{}': {}",
                        file.getFileName(), exception.getMessage(), exception);
            }
            throw exception;
        }

        ImportSession completedSession = runningSession.finish(
                ImportSessionStatus.COMPLETED, Instant.now(), counters[0], counters[1], counters[2],
                counters[3], counters[4], Optional.empty());
        try {
            persistence.completeImport(completedSession, alerts);
        } catch (RuntimeException persistenceFailure) {
            ImportSession failedSession = runningSession.finish(
                    ImportSessionStatus.FAILED, Instant.now(), counters[0], counters[1], counters[2],
                    counters[3], counters[4], Optional.of("Alert/session persistence failed."));
            try {
                persistence.finishImport(failedSession);
            } catch (RuntimeException statusFailure) {
                persistenceFailure.addSuppressed(statusFailure);
            }
            throw new PersistenceException(
                    "PCAP processing completed but persistent storage failed; import is not complete",
                    persistenceFailure);
        }
        if (counters[4] > alerts.size()) {
            LOGGER.warn("Alert repository input for import {} was capped at {} generated findings",
                    importId, ALERTS_PER_IMPORT_LIMIT);
        }
        LOGGER.info("PCAP import complete and persisted: file='{}', records={}, parsed={}, unsupported={}, malformed={}, alerts={}",
                file.getFileName(), counters[0], counters[1], counters[2], counters[3], counters[4]);

        return new ImportSummary(
                counters[0], counters[1], counters[2], counters[3], counters[4],
                detectionEngine.aggregator().trackedSourceCount(),
                detectionEngine.aggregator().latePacketsDropped(),
                detectionEngine.aggregator().capacityDroppedPackets(),
                detectionEngine.aggregator().capacityEvictedSources(),
                detectionEngine.aggregator().capacityEvictedBuckets(),
                alerts.size(),
                counters[4] - alerts.size(),
                alerts,
                List.copyOf(traffic));
    }
}
