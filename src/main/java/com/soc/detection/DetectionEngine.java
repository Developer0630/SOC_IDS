package com.soc.detection;

import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class DetectionEngine {
    private final List<DetectionRule> rules;
    private final TrafficAggregator aggregator;
    private final Duration suppressionWindow;
    private final UUID importId;
    private final Map<String, Instant> lastAlertByRuleAndSource = new LinkedHashMap<>(16, 0.75f, true);

    public DetectionEngine(List<DetectionRule> rules, Duration suppressionWindow, UUID importId) {
        if (rules == null || rules.isEmpty()) {
            throw new IllegalArgumentException("At least one detection rule is required");
        }
        this.rules = List.copyOf(rules);
        this.suppressionWindow = Objects.requireNonNull(suppressionWindow, "suppressionWindow");
        if (suppressionWindow.isNegative()) {
            throw new IllegalArgumentException("Suppression window cannot be negative");
        }
        this.importId = Objects.requireNonNull(importId, "importId");
        Duration maxWindow = this.rules.stream()
                .map(rule -> rule.config().observationWindow())
                .max(Duration::compareTo)
                .orElseThrow();
        this.aggregator = new TrafficAggregator(maxWindow);
    }

    public static DetectionEngine defaults(UUID importId) {
        return defaults(importId, DetectionRuleSettings.defaults());
    }

    public static DetectionEngine defaults(UUID importId, DetectionRuleSettings settings) {
        Objects.requireNonNull(settings, "settings");
        return new DetectionEngine(
                List.of(
                        new PortScanRule(settings.portScanConfig()),
                        new SynRateRule(settings.synConfig()),
                        new IcmpThresholdRule(settings.icmpConfig())),
                Duration.ofSeconds(10),
                importId);
    }

    public List<IntrusionAlert> process(NetworkPacket packet) {
        Objects.requireNonNull(packet, "packet");
        aggregator.record(packet);
        if (packet.sourceAddress().isEmpty()) {
            return List.of();
        }

        List<IntrusionAlert> findings = new ArrayList<>();
        for (DetectionRule rule : rules) {
            DetectionRuleConfig config = rule.config();
            if (!config.enabled()) {
                continue;
            }
            TrafficWindowSnapshot snapshot = aggregator.snapshot(
                    packet.sourceAddress().get(), packet.timestamp(), config.observationWindow());
            rule.evaluate(packet, snapshot).ifPresent(finding -> {
                String suppressionKey = finding.ruleId() + "\u0000"
                        + finding.sourceAddress().orElse("unavailable");
                Instant previous = lastAlertByRuleAndSource.get(suppressionKey);
                if (previous != null
                        && !packet.timestamp().isAfter(previous.plus(suppressionWindow))) {
                    return;
                }
                lastAlertByRuleAndSource.put(suppressionKey, packet.timestamp());
                if (lastAlertByRuleAndSource.size() > 10_000) {
                    Iterator<String> oldest = lastAlertByRuleAndSource.keySet().iterator();
                    oldest.next();
                    oldest.remove();
                }
                findings.add(new IntrusionAlert(
                        UUID.randomUUID(),
                        packet.timestamp(),
                        finding.sourceAddress(),
                        finding.destinationAddress(),
                        finding.ruleId(),
                        finding.severity(),
                        finding.description(),
                        finding.evidence(),
                        AlertStatus.NEW,
                        importId));
            });
        }
        return List.copyOf(findings);
    }

    public TrafficAggregator aggregator() {
        return aggregator;
    }
}
