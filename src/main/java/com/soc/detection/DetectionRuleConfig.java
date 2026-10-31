package com.soc.detection;

import com.soc.model.RiskLevel;

import java.time.Duration;
import java.util.Objects;

public record DetectionRuleConfig(
        String id,
        String name,
        String description,
        long threshold,
        Duration observationWindow,
        RiskLevel severity,
        boolean enabled) {

    public DetectionRuleConfig {
        if (id == null || id.isBlank() || name == null || name.isBlank()
                || description == null || description.isBlank()) {
            throw new IllegalArgumentException("Rule ID, name, and description are required");
        }
        if (threshold <= 0) {
            throw new IllegalArgumentException("Rule threshold must be greater than zero");
        }
        Objects.requireNonNull(observationWindow, "observationWindow");
        if (observationWindow.isZero() || observationWindow.isNegative()
                || observationWindow.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("Observation window must be between 0 and 1 hour");
        }
        Objects.requireNonNull(severity, "severity");
    }
}
