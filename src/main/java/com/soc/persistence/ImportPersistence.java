package com.soc.persistence;

import com.soc.detection.AlertRepository;
import com.soc.model.IntrusionAlert;

import java.util.List;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

public interface ImportPersistence extends AlertRepository,
        ImportSessionRepository, DetectionRuleSettingsRepository {
    List<IntrusionAlert> findRecent(int limit);

    List<IntrusionAlert> findByImport(UUID importId, int limit);

    long countAlerts();

    long countCriticalAlerts();

    Optional<Path> databasePath();

    default String storageDescription() {
        return databasePath().map(Path::toString).orElse("not configured");
    }
}
