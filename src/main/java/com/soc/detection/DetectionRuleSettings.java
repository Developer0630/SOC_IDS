package com.soc.detection;

import com.soc.model.RiskLevel;

import java.time.Duration;

public record DetectionRuleSettings(
        long portScanThreshold,
        long synThreshold,
        long icmpThreshold,
        long observationWindowSeconds,
        boolean portScanEnabled,
        boolean synEnabled,
        boolean icmpEnabled) {

    public DetectionRuleSettings {
        validateThreshold(portScanThreshold, "Port scan");
        validateThreshold(synThreshold, "SYN");
        validateThreshold(icmpThreshold, "ICMP");
        if (observationWindowSeconds <= 0 || observationWindowSeconds > 3600) {
            throw new IllegalArgumentException("Observation window must be between 1 and 3600 seconds");
        }
    }

    public static DetectionRuleSettings defaults() {
        return new DetectionRuleSettings(15, 100, 100, 10, true, true, true);
    }

    public DetectionRuleConfig portScanConfig() {
        return new DetectionRuleConfig(
                PortScanRule.ID, "Port scan heuristic",
                "Observed TCP traffic to many distinct destination ports. Connection success is not determined.",
                portScanThreshold, Duration.ofSeconds(observationWindowSeconds),
                RiskLevel.HIGH, portScanEnabled);
    }

    public DetectionRuleConfig synConfig() {
        return new DetectionRuleConfig(
                SynRateRule.ID, "TCP SYN rate heuristic",
                "High observed bare TCP SYN volume; this heuristic does not confirm a denial-of-service attack.",
                synThreshold, Duration.ofSeconds(observationWindowSeconds),
                RiskLevel.HIGH, synEnabled);
    }

    public DetectionRuleConfig icmpConfig() {
        return new DetectionRuleConfig(
                IcmpThresholdRule.ID, "ICMP traffic threshold",
                "Observed ICMP packet rate exceeds the configured threshold; ICMP is not inherently malicious.",
                icmpThreshold, Duration.ofSeconds(observationWindowSeconds),
                RiskLevel.MEDIUM, icmpEnabled);
    }

    private static void validateThreshold(long threshold, String rule) {
        if (threshold <= 0) {
            throw new IllegalArgumentException(rule + " threshold must be greater than zero");
        }
    }
}
