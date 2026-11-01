package com.soc.detection;

import com.soc.model.IntrusionAlert;
import com.soc.model.RiskLevel;
import com.soc.persistence.ImportPersistence;
import com.soc.persistence.ImportSession;
import com.soc.persistence.ImportSessionStatus;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class InMemoryAlertRepository implements ImportPersistence {
    public static final int DEFAULT_CAPACITY = 5000;

    private final int capacity;
    private final ArrayDeque<IntrusionAlert> alerts = new ArrayDeque<>();
    private final Map<UUID, ImportSession> imports = new HashMap<>();
    private DetectionRuleSettings ruleSettings;

    public InMemoryAlertRepository() {
        this(DEFAULT_CAPACITY);
    }

    public InMemoryAlertRepository(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("Alert repository capacity must be positive");
        }
        this.capacity = capacity;
    }

    @Override
    public synchronized void saveAll(List<IntrusionAlert> newAlerts) {
        Objects.requireNonNull(newAlerts, "newAlerts");
        for (IntrusionAlert alert : newAlerts) {
            alerts.addLast(Objects.requireNonNull(alert, "alert"));
            while (alerts.size() > capacity) {
                alerts.removeFirst();
            }
        }
    }

    @Override
    public synchronized List<IntrusionAlert> findAll() {
        return List.copyOf(new ArrayList<>(alerts));
    }

    @Override
    public synchronized void startImport(ImportSession session) {
        if (session.status() != ImportSessionStatus.RUNNING
                || imports.putIfAbsent(session.id(), session) != null) {
            throw new IllegalStateException("Import session is not new and running");
        }
    }

    @Override
    public synchronized void completeImport(ImportSession session, List<IntrusionAlert> newAlerts) {
        Objects.requireNonNull(newAlerts, "newAlerts");
        requireRunning(session);
        for (IntrusionAlert alert : newAlerts) {
            if (!alert.importId().equals(session.id())) {
                throw new IllegalArgumentException("Alert import reference does not match session");
            }
        }
        alerts.addAll(newAlerts);
        while (alerts.size() > capacity) {
            alerts.removeFirst();
        }
        imports.put(session.id(), session);
    }

    @Override
    public synchronized void finishImport(ImportSession session) {
        requireRunning(session);
        if (session.status() == ImportSessionStatus.RUNNING
                || session.status() == ImportSessionStatus.COMPLETED) {
            throw new IllegalArgumentException("A failure or cancellation status is required");
        }
        imports.put(session.id(), session);
    }

    @Override
    public synchronized List<ImportSession> recentImports(int limit) {
        validateLimit(limit);
        return imports.values().stream()
                .sorted(Comparator.comparing(ImportSession::startedAt).reversed())
                .limit(limit)
                .toList();
    }

    @Override
    public synchronized void markRunningImportsInterrupted() {
        imports.replaceAll((id, session) -> session.status() == ImportSessionStatus.RUNNING
                ? session.finish(ImportSessionStatus.INTERRUPTED, java.time.Instant.now(),
                        session.totalRecords(), session.parsedPackets(), session.unsupportedPackets(),
                        session.malformedPackets(), session.alertsCreated(),
                        Optional.of("Application stopped before this import completed."))
                : session);
    }

    @Override
    public synchronized List<IntrusionAlert> findRecent(int limit) {
        validateLimit(limit);
        List<IntrusionAlert> result = new ArrayList<>(Math.min(limit, alerts.size()));
        var iterator = alerts.descendingIterator();
        while (iterator.hasNext() && result.size() < limit) {
            result.add(iterator.next());
        }
        return List.copyOf(result);
    }

    @Override
    public synchronized List<IntrusionAlert> findByImport(UUID importId, int limit) {
        Objects.requireNonNull(importId, "importId");
        validateLimit(limit);
        return alerts.stream()
                .filter(alert -> alert.importId().equals(importId))
                .sorted(Comparator.comparing(IntrusionAlert::timestamp).reversed())
                .limit(limit)
                .toList();
    }

    @Override
    public synchronized long countAlerts() {
        return alerts.size();
    }

    @Override
    public synchronized long countCriticalAlerts() {
        return alerts.stream().filter(alert -> alert.severity() == RiskLevel.CRITICAL).count();
    }

    @Override
    public synchronized DetectionRuleSettings loadOrCreateRuleSettings() {
        if (ruleSettings == null) {
            ruleSettings = DetectionRuleSettings.defaults();
        }
        return ruleSettings;
    }

    @Override
    public synchronized void saveRuleSettings(DetectionRuleSettings settings) {
        ruleSettings = Objects.requireNonNull(settings, "settings");
    }

    @Override
    public Optional<java.nio.file.Path> databasePath() {
        return Optional.empty();
    }

    private void requireRunning(ImportSession session) {
        Objects.requireNonNull(session, "session");
        ImportSession current = imports.get(session.id());
        if (current == null || current.status() != ImportSessionStatus.RUNNING) {
            throw new IllegalStateException("Import session is missing or not RUNNING");
        }
    }

    private static void validateLimit(int limit) {
        if (limit <= 0 || limit > 1000) {
            throw new IllegalArgumentException("Query limit must be between 1 and 1000");
        }
    }
}
