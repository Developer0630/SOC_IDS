package com.soc.persistence;

import com.soc.detection.DetectionRuleSettings;
import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.RiskLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfEnvironmentVariable(
        named = "SENTINEL_MYSQL_TEST_URL",
        matches = "jdbc:mysql://[^/]+/[^?]*_test(?:\\?.*)?")
class MySqlImportPersistenceTest {
    private static MySqlDatabase database;
    private static MySqlImportPersistence persistence;

    @TempDir
    Path temporaryDirectory;
    private final Set<UUID> createdImportIds = new LinkedHashSet<>();
    private List<RuleConfigSnapshot> previousRuleConfigs = List.of();
    private List<RunningSessionSnapshot> previousRunningSessions = List.of();
    private Path sqliteSourcePath;
    private String attemptedInvalidRuleId;

    @BeforeAll
    static void initializeDedicatedTestDatabase() {
        String url = System.getenv("SENTINEL_MYSQL_TEST_URL");
        String username = System.getenv("SENTINEL_MYSQL_TEST_USER");
        String password = System.getenv("SENTINEL_MYSQL_TEST_PASSWORD");
        if (url == null || !url.matches("jdbc:mysql://[^/]+/[^?]*_test(?:\\?.*)?")) {
            throw new IllegalStateException(
                    "SENTINEL_MYSQL_TEST_URL must target a JDBC database whose name ends in _test");
        }
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalStateException(
                    "SENTINEL_MYSQL_TEST_USER and SENTINEL_MYSQL_TEST_PASSWORD must be configured");
        }
        database = new MySqlDatabase(new MySqlDatabaseConfig(url, username, password));
        verifyTargetMariaDbVersion();
        database.initialize();
        persistence = new MySqlImportPersistence(database);
    }

    @BeforeEach
    void captureRuleConfigurations() {
        List<RuleConfigSnapshot> ruleSnapshots = new ArrayList<>();
        List<RunningSessionSnapshot> sessionSnapshots = new ArrayList<>();
        try (Connection connection = database.openConnection()) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms
                    FROM detection_rule_configs
                    """);
                 ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    ruleSnapshots.add(new RuleConfigSnapshot(
                            result.getString("rule_id"),
                            result.getLong("threshold"),
                            result.getLong("window_seconds"),
                            result.getInt("enabled"),
                            result.getLong("updated_at_epoch_ms")));
                }
            }
            try (PreparedStatement runningSessions = connection.prepareStatement("""
                    SELECT id, status, completed_at_epoch_ms, error_message
                    FROM import_sessions WHERE status = 'RUNNING'
                    """);
                 ResultSet running = runningSessions.executeQuery()) {
                while (running.next()) {
                    long completedAt = running.getLong("completed_at_epoch_ms");
                    Long completedAtEpochMs = running.wasNull() ? null : completedAt;
                    sessionSnapshots.add(new RunningSessionSnapshot(
                            UUID.fromString(running.getString("id")),
                            running.getString("status"),
                            completedAtEpochMs,
                            running.getString("error_message")));
                }
            }
        } catch (SQLException exception) {
            throw new PersistenceException(
                    "Unable to snapshot MariaDB integration test state", exception);
        }
        previousRuleConfigs = List.copyOf(ruleSnapshots);
        previousRunningSessions = List.copyOf(sessionSnapshots);
    }

    @AfterEach
    void removeTestDataAndRestoreRuleConfigurations() {
        try (Connection connection = database.openConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM intrusion_alerts WHERE import_session_id = ?")) {
                    for (UUID importId : createdImportIds) {
                        statement.setString(1, importId.toString());
                        statement.addBatch();
                    }
                    statement.executeBatch();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM import_sessions WHERE id = ?")) {
                    for (UUID importId : createdImportIds) {
                        statement.setString(1, importId.toString());
                        statement.addBatch();
                    }
                    statement.executeBatch();
                }
                restoreRunningSessions(connection);
                if (sqliteSourcePath != null) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "DELETE FROM sentinel_data_migrations WHERE source_path = ?")) {
                        statement.setString(1, sqliteSourcePath.toString());
                        statement.executeUpdate();
                    }
                }
                if (attemptedInvalidRuleId != null) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "DELETE FROM detection_rule_configs WHERE rule_id = ?")) {
                        statement.setString(1, attemptedInvalidRuleId);
                        statement.executeUpdate();
                    }
                }
                restoreRuleConfigurations(connection);
                connection.commit();
            } catch (SQLException exception) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    exception.addSuppressed(rollbackFailure);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new PersistenceException(
                    "Unable to clean up MariaDB integration test data", exception);
        }
    }

    private static void verifyTargetMariaDbVersion() {
        try (Connection connection = database.openConnection()) {
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT VERSION(), @@version_comment")) {
                if (!result.next()) {
                    throw new IllegalStateException(
                            "Unable to identify the MariaDB integration server version");
                }
                String serverVersion = result.getString(1);
                String versionComment = result.getString(2);
                boolean isMariaDb = (serverVersion + " " + versionComment)
                        .toLowerCase(Locale.ROOT).contains("mariadb");
                boolean isTargetVersion = Pattern.compile("(?:^|-)10\\.4\\.32(?:-|$)")
                        .matcher(serverVersion).find();
                if (!isMariaDb || !isTargetVersion) {
                    throw new IllegalStateException(
                            "Integration tests require MariaDB 10.4.32; found version "
                                    + serverVersion + " ("
                                    + versionComment + ")");
                }
            }
        } catch (SQLException exception) {
            throw new PersistenceException(
                    "Unable to verify the configured MariaDB integration server", exception);
        }
    }

    @Test
    void roundTripsSessionsAlertsEvidenceRulesAndPersistsAcrossConnections() {
        DetectionRuleSettings originalSettings = persistence.loadOrCreateRuleSettings();
        DetectionRuleSettings desired = new DetectionRuleSettings(27, 105, 45, 17, false, true, false);
        UUID importId = UUID.randomUUID();
        ImportSession running = start("mysql-roundtrip.pcap", importId);
        IntrusionAlert expected = alert(importId, Instant.parse("2025-02-03T04:05:06.123456789Z"));
        try {
            persistence.saveRuleSettings(desired);
            persistence.completeImport(finish(running, ImportSessionStatus.COMPLETED, 2, 1),
                    List.of(expected));

            MySqlImportPersistence reopened =
                    new MySqlImportPersistence(new MySqlDatabase(databaseConfig()));
            assertEquals(expected, reopened.findByImport(importId, 10).get(0));
            assertEquals(expected.evidence(), reopened.findByImport(importId, 10).get(0).evidence());
            assertEquals(ImportSessionStatus.COMPLETED, find(reopened, importId).status());
            assertEquals(desired, reopened.loadOrCreateRuleSettings());
        } finally {
            persistence.saveRuleSettings(originalSettings);
        }
    }

    @Test
    void repeatedSchemaInitializationDoesNotRemovePersistedRows() {
        UUID importId = UUID.randomUUID();
        ImportSession running = start("mysql-reinitialize.pcap", importId);
        persistence.completeImport(
                finish(running, ImportSessionStatus.COMPLETED, 1, 0), List.of());

        database.initialize();

        assertEquals(ImportSessionStatus.COMPLETED, find(persistence, importId).status());
    }

    @Test
    void rollsBackAlertAndSessionTogetherAndRejectsMissingForeignKey() {
        UUID importId = UUID.randomUUID();
        ImportSession running = start("mysql-rollback.pcap", importId);
        IntrusionAlert duplicate = alert(importId, Instant.EPOCH);

        PersistenceException duplicateFailure = assertThrows(PersistenceException.class,
                () -> persistence.completeImport(
                        finish(running, ImportSessionStatus.COMPLETED, 2, 2),
                        List.of(duplicate, duplicate)));
        assertIntegrityConstraintViolation(duplicateFailure.getCause());
        assertEquals(ImportSessionStatus.RUNNING, find(persistence, importId).status());
        assertEquals(0, persistence.findByImport(importId, 10).size());
        PersistenceException foreignKeyFailure = assertThrows(PersistenceException.class,
                () -> persistence.saveAll(List.of(alert(UUID.randomUUID(), Instant.EPOCH))));
        assertIntegrityConstraintViolation(foreignKeyFailure.getCause());
    }

    @Test
    void enforcesCheckConstraintsForStatusesAndRuleSettings() throws Exception {
        try (Connection connection = database.openConnection();
             PreparedStatement sessionInsert = connection.prepareStatement("""
                     INSERT INTO import_sessions(
                         id, file_name, started_at_epoch_ms, status, total_records, parsed_packets,
                         unsupported_packets, malformed_packets, alerts_created
                     ) VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0)
                     """)) {
            UUID invalidSessionId = UUID.randomUUID();
            createdImportIds.add(invalidSessionId);
            sessionInsert.setString(1, invalidSessionId.toString());
            sessionInsert.setString(2, "invalid-state.pcap");
            sessionInsert.setLong(3, System.currentTimeMillis());
            sessionInsert.setString(4, "INVALID");
            SQLException statusFailure = assertThrows(SQLException.class, sessionInsert::executeUpdate);
            assertIntegrityConstraintViolation(statusFailure);
        }
        try (Connection connection = database.openConnection();
             PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO detection_rule_configs(
                        rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms
                    ) VALUES (?, 0, 0, 2, 0)
                    """)) {
            attemptedInvalidRuleId = "X" + UUID.randomUUID().toString().replace("-", "").substring(0, 31);
            statement.setString(1, attemptedInvalidRuleId);
            SQLException ruleFailure = assertThrows(SQLException.class, statement::executeUpdate);
            assertIntegrityConstraintViolation(ruleFailure);
        }
    }

    @Test
    void recoversRunningSessionsAndBoundsHistoryQueries() {
        UUID importId = UUID.randomUUID();
        ImportSession running = start("mysql-interrupted.pcap", importId);
        UUID failedId = UUID.randomUUID();
        UUID cancelledId = UUID.randomUUID();
        ImportSession failed = start("mysql-failed.pcap", failedId);
        ImportSession cancelled = start("mysql-cancelled.pcap", cancelledId);
        persistence.finishImport(finish(failed, ImportSessionStatus.FAILED, 4, 0)
                .finish(ImportSessionStatus.FAILED, Instant.now(), 4, 2, 0, 2, 0,
                        Optional.of("Malformed source record")));
        persistence.finishImport(finish(cancelled, ImportSessionStatus.CANCELLED, 1, 0));
        for (int index = 0; index < 3; index++) {
            UUID completedId = UUID.randomUUID();
            ImportSession session = start("mysql-history-" + index + ".pcap", completedId);
            persistence.completeImport(
                    finish(session, ImportSessionStatus.COMPLETED, 1, 1),
                    List.of(alert(completedId, Instant.ofEpochSecond(index + 1))));
        }

        persistence.markRunningImportsInterrupted();

        assertEquals(ImportSessionStatus.INTERRUPTED, find(persistence, importId).status());
        assertEquals(ImportSessionStatus.FAILED, find(persistence, failedId).status());
        assertEquals(ImportSessionStatus.CANCELLED, find(persistence, cancelledId).status());
        assertEquals(1, persistence.findRecent(1).size());
        assertEquals(1, persistence.recentImports(1).size());
        assertThrows(IllegalArgumentException.class, () -> persistence.findRecent(1001));
        assertEquals(1, persistence.findByImport(
                persistence.recentImports(1000).stream()
                        .filter(session -> session.fileName().equals("mysql-history-0.pcap"))
                        .findFirst().orElseThrow().id(),
                1).size());
    }

    @Test
    void migratesSqliteDataReadOnlyAndDoesNotDuplicateOnRerun() throws Exception {
        Path sourceFile = temporaryDirectory.resolve("legacy-sentinel.db");
        SqliteDatabase sqlite = new SqliteDatabase(sourceFile);
        sqlite.initialize();
        sqliteSourcePath = sourceFile.toRealPath();
        SqliteImportPersistence oldPersistence = new SqliteImportPersistence(sqlite);
        DetectionRuleSettings settings = new DetectionRuleSettings(19, 110, 67, 22, true, false, true);
        oldPersistence.saveRuleSettings(settings);
        UUID importId = UUID.randomUUID();
        ImportSession running = start(oldPersistence, "legacy.pcap", importId);
        IntrusionAlert expected = alert(importId, Instant.parse("2024-06-07T08:09:10.987654321Z"));
        oldPersistence.completeImport(
                finish(running, ImportSessionStatus.COMPLETED, 3, 1), List.of(expected));
        long sourceBytesBefore = java.nio.file.Files.size(sourceFile);

        SqliteToMySqlMigration migrator = new SqliteToMySqlMigration(database);
        SqliteToMySqlMigration.MigrationResult first = migrator.migrate(sourceFile);
        SqliteToMySqlMigration.MigrationResult second = migrator.migrate(sourceFile);

        assertEquals(1, first.sessions());
        assertEquals(1, first.alerts());
        assertEquals(3, first.ruleConfigs());
        assertTrue(second.alreadyMigrated());
        assertEquals(sourceBytesBefore, java.nio.file.Files.size(sourceFile));
        assertEquals(1, persistence.findByImport(importId, 10).size());
        assertEquals(expected, persistence.findByImport(importId, 10).get(0));
        assertEquals(settings, persistence.loadOrCreateRuleSettings());
    }

    private static MySqlDatabaseConfig databaseConfig() {
        return new MySqlDatabaseConfig(
                System.getenv("SENTINEL_MYSQL_TEST_URL"),
                System.getenv("SENTINEL_MYSQL_TEST_USER"),
                System.getenv("SENTINEL_MYSQL_TEST_PASSWORD"));
    }

    private ImportSession start(String fileName, UUID id) {
        createdImportIds.add(id);
        ImportSession session = ImportSession.running(id, fileName, Instant.now());
        persistence.startImport(session);
        return session;
    }

    private ImportSession start(
            SqliteImportPersistence repository, String fileName, UUID id) {
        createdImportIds.add(id);
        ImportSession session = ImportSession.running(id, fileName, Instant.now());
        repository.startImport(session);
        return session;
    }

    private static ImportSession finish(
            ImportSession running, ImportSessionStatus status, long records, long alerts) {
        return running.finish(status, Instant.now(), records, records, 0, 0, alerts, Optional.empty());
    }

    private static ImportSession find(MySqlImportPersistence repository, UUID id) {
        return repository.recentImports(1000).stream()
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

    private void restoreRuleConfigurations(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    DELETE FROM detection_rule_configs
                    WHERE rule_id IN ('PORT_SCAN', 'SYN_RATE', 'ICMP_RATE')
                    """);
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO detection_rule_configs(
                    rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms
                ) VALUES (?, ?, ?, ?, ?)
                """)) {
            for (RuleConfigSnapshot snapshot : previousRuleConfigs) {
                statement.setString(1, snapshot.ruleId());
                statement.setLong(2, snapshot.threshold());
                statement.setLong(3, snapshot.windowSeconds());
                statement.setInt(4, snapshot.enabled());
                statement.setLong(5, snapshot.updatedAtEpochMs());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private void restoreRunningSessions(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE import_sessions
                SET status = ?, completed_at_epoch_ms = ?, error_message = ?
                WHERE id = ?
                """)) {
            for (RunningSessionSnapshot snapshot : previousRunningSessions) {
                statement.setString(1, snapshot.status());
                if (snapshot.completedAtEpochMs() == null) {
                    statement.setNull(2, java.sql.Types.BIGINT);
                } else {
                    statement.setLong(2, snapshot.completedAtEpochMs());
                }
                if (snapshot.errorMessage() == null) {
                    statement.setNull(3, java.sql.Types.VARCHAR);
                } else {
                    statement.setString(3, snapshot.errorMessage());
                }
                statement.setString(4, snapshot.id().toString());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private static void assertIntegrityConstraintViolation(Throwable failure) {
        SQLException exception = assertInstanceOf(SQLException.class, failure);
        assertTrue(exception.getSQLState() != null && exception.getSQLState().startsWith("23"),
                "Expected a SQL integrity constraint violation, got SQLState "
                        + exception.getSQLState());
    }

    private record RuleConfigSnapshot(
            String ruleId, long threshold, long windowSeconds, int enabled, long updatedAtEpochMs) {
    }

    private record RunningSessionSnapshot(
            UUID id, String status, Long completedAtEpochMs, String errorMessage) {
    }
}
