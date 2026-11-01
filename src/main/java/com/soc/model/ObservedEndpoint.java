package com.soc.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

public record ObservedEndpoint(
        String ipAddress,
        Optional<String> macAddress,
        long packetsSeen,
        Instant firstSeen,
        Instant lastSeen) {

    public ObservedEndpoint {
        if (ipAddress == null || ipAddress.isBlank()) {
            throw new IllegalArgumentException("Observed IP address cannot be blank");
        }
        macAddress = Objects.requireNonNull(macAddress, "macAddress");
        Objects.requireNonNull(firstSeen, "firstSeen");
        Objects.requireNonNull(lastSeen, "lastSeen");
        if (packetsSeen < 0 || lastSeen.isBefore(firstSeen)) {
            throw new IllegalArgumentException("Invalid observed endpoint counters or timestamps");
        }
    }
}
