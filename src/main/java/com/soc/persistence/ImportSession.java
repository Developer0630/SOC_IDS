package com.soc.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public record ImportSession(
        UUID id,
        String fileName,
        Instant startedAt,
        Optional<Instant> completedAt,
        ImportSessionStatus status,
        long totalRecords,
        long parsedPackets,
        long unsupportedPackets,
        long malformedPackets,
        long alertsCreated,
        Optional<String> errorMessage) {

    public ImportSession {
        Objects.requireNonNull(id, "id");
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("Import file name cannot be blank");
        }
        Objects.requireNonNull(startedAt, "startedAt");
        completedAt = Objects.requireNonNull(completedAt, "completedAt");
        Objects.requireNonNull(status, "status");
        errorMessage = Objects.requireNonNull(errorMessage, "errorMessage");
        if (totalRecords < 0 || parsedPackets < 0 || unsupportedPackets < 0
                || malformedPackets < 0 || alertsCreated < 0) {
            throw new IllegalArgumentException("Import counters cannot be negative");
        }
        if (status == ImportSessionStatus.RUNNING && completedAt.isPresent()) {
            throw new IllegalArgumentException("Running import cannot have a completion time");
        }
    }

    public static ImportSession running(UUID id, String fileName, Instant startedAt) {
        return new ImportSession(id, fileName, startedAt, Optional.empty(),
                ImportSessionStatus.RUNNING, 0, 0, 0, 0, 0, Optional.empty());
    }

    public ImportSession finish(
            ImportSessionStatus finalStatus,
            Instant finishedAt,
            long totalRecords,
            long parsedPackets,
            long unsupportedPackets,
            long malformedPackets,
            long alertsCreated,
            Optional<String> errorMessage) {
        if (finalStatus == ImportSessionStatus.RUNNING) {
            throw new IllegalArgumentException("Terminal import status is required");
        }
        return new ImportSession(id, fileName, startedAt, Optional.of(finishedAt), finalStatus,
                totalRecords, parsedPackets, unsupportedPackets, malformedPackets, alertsCreated,
                errorMessage);
    }
}
