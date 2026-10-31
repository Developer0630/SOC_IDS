package com.soc.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public record IntrusionAlert(
        UUID id,
        Instant timestamp,
        Optional<String> sourceAddress,
        Optional<String> destinationAddress,
        String ruleId,
        RiskLevel severity,
        String description,
        String evidence,
        AlertStatus status,
        UUID importId) {

    public IntrusionAlert {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(timestamp, "timestamp");
        sourceAddress = Objects.requireNonNull(sourceAddress, "sourceAddress");
        destinationAddress = Objects.requireNonNull(destinationAddress, "destinationAddress");
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException("Rule ID cannot be blank");
        }
        Objects.requireNonNull(severity, "severity");
        if (description == null || description.isBlank()) {
            throw new IllegalArgumentException("Description cannot be blank");
        }
        if (evidence == null || evidence.isBlank()) {
            throw new IllegalArgumentException("Evidence cannot be blank");
        }
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(importId, "importId");
    }
}
