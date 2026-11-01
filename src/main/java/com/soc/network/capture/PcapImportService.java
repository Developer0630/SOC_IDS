package com.soc.network.capture;

import com.soc.detection.AlertRepository;
import com.soc.detection.DetectionEngine;
import com.soc.detection.DetectionRuleSettings;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.network.parser.PacketParseResult;
import com.soc.network.parser.PcapPacketParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class PcapImportService {
    private static final Logger LOGGER = LoggerFactory.getLogger(PcapImportService.class);
    private static final int TRAFFIC_SAMPLE_LIMIT = 500;
    private static final int ALERTS_PER_IMPORT_LIMIT = 2000;

    private final PcapReadConfig readConfig;
    private final AlertRepository alertRepository;
    private final PcapFileReader reader;
    private final PcapPacketParser parser;

    public PcapImportService(PcapReadConfig readConfig, AlertRepository alertRepository) {
        this(readConfig, alertRepository, new PcapFileReader(), new PcapPacketParser());
    }

    PcapImportService(
            PcapReadConfig readConfig,
            AlertRepository alertRepository,
            PcapFileReader reader,
            PcapPacketParser parser) {
        this.readConfig = Objects.requireNonNull(readConfig, "readConfig");
        this.alertRepository = Objects.requireNonNull(alertRepository, "alertRepository");
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
        Objects.requireNonNull(ruleSettings, "ruleSettings");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(progress, "progress");

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
            if (exception instanceof CancellationException) {
                throw exception;
            }
            LOGGER.error("PCAP import failed for '{}': {}",
                    file == null ? "unknown file" : file.getFileName(), exception.getMessage(), exception);
            throw exception;
        }

        alertRepository.saveAll(alerts);
        if (counters[4] > alerts.size()) {
            LOGGER.warn("Alert repository input for import {} was capped at {} generated findings",
                    importId, ALERTS_PER_IMPORT_LIMIT);
        }
        LOGGER.info("PCAP import complete: file='{}', records={}, parsed={}, unsupported={}, malformed={}, alerts={}",
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
