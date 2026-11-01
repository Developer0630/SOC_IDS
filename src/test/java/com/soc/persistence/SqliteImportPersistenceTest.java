package com.soc.persistence;

import com.soc.detection.DetectionRuleSettings;
import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.RiskLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqliteImportPersistenceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void initializesSchemaAndReopeningDoesNotLoseSavedAlertsOrSettings() {
        Path path = temporaryDirectory.resolve("sentinel.db");
        SqliteDatabase database = new SqliteDatabase(path);
        database.initialize();
        assertEquals(SqliteDatabase.SCHEMA_VERSION, database.schemaVersion());
        SqliteImportPersistence first = new SqliteImportPersistence(database);
        DetectionRuleSettings settings =
                new DetectionRuleSettings(23, 101, 42, 17, false, true, false);
        first.saveRuleSettings(settings);
        ImportSession running = start(first, "capture.pcap");
        ImportSession completed = finish(running, ImportSessionStatus.COMPLETED, 2, 1);
        IntrusionAlert expected = alert(running.id(), Instant.parse("2025-01-01T00:00:00.123456789Z"));
        first.completeImport(completed, List.of(expected));

        SqliteDatabase reopenedDatabase = new SqliteDatabase(path);
        reopenedDatabase.initialize();
        assertEquals(SqliteDatabase.SCHEMA_VERSION, reopenedDatabase.schemaVersion());
        SqliteImportPersistence reopened = new SqliteImportPersistence(reopenedDatabase);

        assertEquals(1, reopened.countAlerts());
        assertEquals(List.of(expected), reopened.findRecent(10));
        assertEquals(settings, reopened.loadOrCreateRuleSettings());
        assertEquals(ImportSessionStatus.COMPLETED, reopened.recentImports(10).get(0).status());
    }

    @Test
    void createsDefaultRuleSettingsOnceAndRejectsInvalidSettings() {
        SqliteImportPersistence persistence = open(temporaryDirectory.resolve("rules.db"));

        assertEquals(DetectionRuleSettings.defaults(), persistence.loadOrCreateRuleSettings());
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionRuleSettings(0, 1, 1, 10, true, true, true));
        assertEquals(DetectionRuleSettings.defaults(), persistence.loadOrCreateRuleSettings());
    }

    @Test
    void storesFailedCancelledAndInterruptedSessionsAsDistinctStatuses() {
        SqliteImportPersistence persistence = open(temporaryDirectory.resolve("statuses.db"));
        ImportSession failedRunning = start(persistence, "failed.pcap");
        ImportSession cancelledRunning = start(persistence, "cancelled.pcap");
        ImportSession abandonedRunning = start(persistence, "abandoned.pcap");
        persistence.finishImport(finish(
                failedRunning, ImportSessionStatus.FAILED, 3, 0)
                .finish(ImportSessionStatus.FAILED, Instant.now(), 3, 2, 0, 1, 0,
                        Optional.of("Malformed record")));
        persistence.finishImport(finish(cancelledRunning, ImportSessionStatus.CANCELLED, 1, 0));
        persistence.markRunningImportsInterrupted();

        assertEquals(3, persistence.recentImports(10).size());
        assertEquals(ImportSessionStatus.FAILED, find(persistence, failedRunning.id()).status());
        assertEquals(ImportSessionStatus.CANCELLED, find(persistence, cancelledRunning.id()).status());
        assertEquals(ImportSessionStatus.INTERRUPTED, find(persistence, abandonedRunning.id()).status());
        assertTrue(find(persistence, failedRunning.id()).errorMessage().orElseThrow().contains("Malformed"));
    }

    @Test
    void commitsAlertsAndCompletedSessionAtomicallyAndEnforcesForeignKeys() {
        SqliteImportPersistence persistence = open(temporaryDirectory.resolve("transactions.db"));
        ImportSession running = start(persistence, "atomic.pcap");
        IntrusionAlert duplicate = alert(running.id(), Instant.EPOCH);
        ImportSession completed = finish(running, ImportSessionStatus.COMPLETED, 2, 2);

        assertThrows(PersistenceException.class,
                () -> persistence.completeImport(completed, List.of(duplicate, duplicate)));
        assertEquals(ImportSessionStatus.RUNNING, find(persistence, running.id()).status());
        assertEquals(0, persistence.countAlerts());
        assertThrows(PersistenceException.class,
                () -> persistence.saveAll(List.of(alert(UUID.randomUUID(), Instant.EPOCH))));
        assertEquals(0, persistence.countAlerts());
    }

    @Test
    void queriesAlertsByImportWithBoundedResultsAndDoesNotDuplicateOnReopen() {
        Path path = temporaryDirectory.resolve("history.db");
        SqliteImportPersistence persistence = open(path);
        ImportSession first = start(persistence, "first.pcap");
        ImportSession second = start(persistence, "second.pcap");
        List<IntrusionAlert> firstAlerts = List.of(
                alert(first.id(), Instant.ofEpochSecond(1)),
                alert(first.id(), Instant.ofEpochSecond(2)));
        persistence.completeImport(finish(first, ImportSessionStatus.COMPLETED, 2, 2), firstAlerts);
        persistence.completeImport(
                finish(second, ImportSessionStatus.COMPLETED, 1, 1),
                List.of(alert(second.id(), Instant.ofEpochSecond(3))));

        SqliteImportPersistence reopened = open(path);

        assertEquals(2, reopened.findByImport(first.id(), 10).size());
        assertEquals(1, reopened.findByImport(second.id(), 10).size());
        assertEquals(1, reopened.findByImport(first.id(), 1).size());
        assertEquals(3, reopened.countAlerts());
        assertEquals(3, reopened.findRecent(3).size());
        assertThrows(IllegalArgumentException.class, () -> reopened.findRecent(1001));
    }

    @Test
    void failedOrCancelledImportRetainsProcessedCounters() {
        SqliteImportPersistence persistence = open(temporaryDirectory.resolve("counters.db"));
        ImportSession running = start(persistence, "partial.pcap");
        ImportSession cancelled = running.finish(
                ImportSessionStatus.CANCELLED, Instant.now(), 9, 7, 1, 1, 2,
                Optional.of("Import cancelled"));

        persistence.finishImport(cancelled);

        ImportSession stored = find(persistence, running.id());
        assertEquals(9, stored.totalRecords());
        assertEquals(7, stored.parsedPackets());
        assertEquals(1, stored.unsupportedPackets());
        assertEquals(1, stored.malformedPackets());
        assertEquals(2, stored.alertsCreated());
    }

    private SqliteImportPersistence open(Path path) {
        SqliteDatabase database = new SqliteDatabase(path);
        database.initialize();
        return new SqliteImportPersistence(database);
    }

    private static ImportSession start(SqliteImportPersistence persistence, String fileName) {
        ImportSession session = ImportSession.running(UUID.randomUUID(), fileName, Instant.now());
        persistence.startImport(session);
        return session;
    }

    private static ImportSession finish(
            ImportSession running, ImportSessionStatus status, long records, long alerts) {
        return running.finish(status, Instant.now(), records, records, 0, 0, alerts, Optional.empty());
    }

    private static ImportSession find(SqliteImportPersistence persistence, UUID id) {
        return persistence.recentImports(100).stream()
                .filter(session -> session.id().equals(id))
                .findFirst()
                .orElseThrow();
    }

    private static IntrusionAlert alert(UUID importId, Instant timestamp) {
        return new IntrusionAlert(
                UUID.randomUUID(), timestamp, Optional.of("192.0.2.10"), Optional.empty(),
                "PORT_SCAN", "Port scan heuristic", RiskLevel.HIGH,
                "Observed multiple destination ports", "metric=2; threshold=2",
                AlertStatus.NEW, importId);
    }
}
