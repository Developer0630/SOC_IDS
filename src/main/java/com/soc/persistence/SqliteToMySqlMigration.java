package com.soc.persistence;

import com.soc.detection.DetectionRuleSettings;
import org.sqlite.SQLiteConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SqliteToMySqlMigration {
    private static final Logger LOGGER = LoggerFactory.getLogger(SqliteToMySqlMigration.class);
    private final MySqlDatabase target;

    public SqliteToMySqlMigration(MySqlDatabase target) {
        this.target = Objects.requireNonNull(target, "target");
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Usage: mvn -Dexec.mainClass=com.soc.persistence.SqliteToMySqlMigration "
                            + "-Dexec.args=\"<path-to-sentinel_noc.db>\" exec:java");
        }
        Path source = Path.of(args[0]);
        MySqlDatabase database = MySqlDatabase.fromEnvironment();
        MigrationResult result = new SqliteToMySqlMigration(database).migrate(source);
        System.out.printf(
                "%s: sessions=%d, alerts=%d, ruleConfigs=%d, source=%s%n",
                result.alreadyMigrated() ? "Already migrated (verified source counts)" : "Migration completed",
                result.sessions(),
                result.alerts(),
                result.ruleConfigs(),
                result.source());
    }

    public MigrationResult migrate(Path sqliteFile) {
        Objects.requireNonNull(sqliteFile, "sqliteFile");
        Path sourcePath;
        try {
            sourcePath = sqliteFile.toRealPath();
            if (!Files.isRegularFile(sourcePath) || Files.size(sourcePath) == 0) {
                throw new PersistenceException(
                        "SQLite migration source is not an existing, non-empty regular file: " + sqliteFile,
                        new IOException("SQLite database file is unavailable"));
            }
        } catch (IOException exception) {
            throw new PersistenceException(
                    "SQLite migration source does not exist or cannot be read: " + sqliteFile, exception);
        }

        target.initialize();
        String migrationKey = migrationKey(sourcePath);
        try (Connection source = openReadOnlySource(sourcePath)) {
            int sourceSchema = readSourceSchemaVersion(source);
            if (sourceSchema != SqliteDatabase.SCHEMA_VERSION) {
                throw new SQLException("Only SQLite schema version " + SqliteDatabase.SCHEMA_VERSION
                        + " is supported; source version is " + sourceSchema);
            }
            verifySourceForeignKeys(source);
            SourceCounts sourceCounts = readSourceCounts(source);
            try (Connection destination = target.openConnection()) {
                MigrationResult prior = findCompletedMigration(destination, migrationKey, sourcePath, sourceCounts);
                if (prior != null) {
                    LOGGER.info("SQLite source '{}' was already migrated", sourcePath);
                    return prior;
                }

                destination.setAutoCommit(false);
                try {
                    long sessionsBefore = count(destination, "import_sessions");
                    long alertsBefore = count(destination, "intrusion_alerts");
                    migrateSessions(source, destination);
                    migrateAlerts(source, destination);
                    Map<String, RuleConfigRow> ruleConfigs = migrateRuleConfigs(source, destination);

                    verifyCount(destination, "import_sessions", sessionsBefore, sourceCounts.sessions());
                    verifyCount(destination, "intrusion_alerts", alertsBefore, sourceCounts.alerts());
                    verifyRuleConfigs(destination, ruleConfigs);
                    recordMigration(destination, migrationKey, sourcePath, sourceCounts);
                    destination.commit();
                } catch (SQLException | RuntimeException exception) {
                    rollback(destination, exception);
                    throw exception;
                }
            }
            return new MigrationResult(
                    sourcePath, sourceCounts.sessions(), sourceCounts.alerts(),
                    sourceCounts.ruleConfigs(), false);
        } catch (SQLException exception) {
            LOGGER.error("SQLite-to-MySQL migration failed for source '{}'", sourcePath, exception);
            throw new PersistenceException(
                    "SQLite-to-MySQL migration failed. The SQLite source was opened read-only; "
                            + "the MySQL transaction was rolled back where possible.",
                    exception);
        }
    }

    static Connection openReadOnlySource(Path sourcePath) throws SQLException {
        SQLiteConfig sqliteConfig = new SQLiteConfig();
        sqliteConfig.setReadOnly(true);
        Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + sourcePath, sqliteConfig.toProperties());
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA query_only = ON");
            statement.execute("PRAGMA foreign_keys = ON");
            connection.setAutoCommit(false);
            return connection;
        } catch (SQLException exception) {
            try {
                connection.close();
            } catch (SQLException closeFailure) {
                exception.addSuppressed(closeFailure);
            }
            throw exception;
        }
    }

    private static int readSourceSchemaVersion(Connection source) throws SQLException {
        try (Statement statement = source.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA user_version")) {
            if (!result.next()) {
                throw new SQLException("SQLite did not return its schema version");
            }
            return result.getInt(1);
        }
    }

    private static void verifySourceForeignKeys(Connection source) throws SQLException {
        try (Statement statement = source.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA foreign_key_check")) {
            if (result.next()) {
                throw new SQLException("SQLite source contains a foreign-key violation in table "
                        + result.getString(1));
            }
        }
    }

    private static SourceCounts readSourceCounts(Connection source) throws SQLException {
        return new SourceCounts(
                count(source, "import_sessions"),
                count(source, "intrusion_alerts"),
                count(source, "detection_rule_configs"));
    }

    private static void migrateSessions(Connection source, Connection destination) throws SQLException {
        try (PreparedStatement read = source.prepareStatement("""
                     SELECT id, file_name, started_at_epoch_ms, completed_at_epoch_ms, status,
                            total_records, parsed_packets, unsupported_packets, malformed_packets,
                            alerts_created, error_message
                     FROM import_sessions ORDER BY id
                     """);
             ResultSet rows = read.executeQuery();
             PreparedStatement insert = destination.prepareStatement("""
                     INSERT INTO import_sessions (
                         id, file_name, started_at_epoch_ms, completed_at_epoch_ms, status,
                         total_records, parsed_packets, unsupported_packets, malformed_packets,
                         alerts_created, error_message
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     """)) {
            int pending = 0;
            String batchEndId = null;
            while (rows.next()) {
                batchEndId = rows.getString("id");
                insert.setString(1, batchEndId);
                insert.setString(2, rows.getString("file_name"));
                insert.setLong(3, rows.getLong("started_at_epoch_ms"));
                setNullableLong(insert, 4, rows, "completed_at_epoch_ms");
                insert.setString(5, rows.getString("status"));
                insert.setLong(6, rows.getLong("total_records"));
                insert.setLong(7, rows.getLong("parsed_packets"));
                insert.setLong(8, rows.getLong("unsupported_packets"));
                insert.setLong(9, rows.getLong("malformed_packets"));
                insert.setLong(10, rows.getLong("alerts_created"));
                insert.setString(11, rows.getString("error_message"));
                insert.addBatch();
                if (++pending == 500) {
                    executeBatch(insert, "import sessions", batchEndId);
                    pending = 0;
                }
            }
            if (pending > 0) {
                executeBatch(insert, "import sessions", batchEndId);
            }
        }
    }

    private static void migrateAlerts(Connection source, Connection destination) throws SQLException {
        try (PreparedStatement read = source.prepareStatement("""
                     SELECT id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                            destination_ip, rule_id, rule_name, severity, description, evidence,
                            status, created_at_epoch_ms
                     FROM intrusion_alerts ORDER BY id
                     """);
             ResultSet rows = read.executeQuery();
             PreparedStatement insert = destination.prepareStatement("""
                     INSERT INTO intrusion_alerts (
                         id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                         destination_ip, rule_id, rule_name, severity, description, evidence,
                         status, created_at_epoch_ms
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     """)) {
            int pending = 0;
            String batchEndId = null;
            while (rows.next()) {
                batchEndId = rows.getString("id");
                insert.setString(1, batchEndId);
                insert.setString(2, rows.getString("import_session_id"));
                insert.setLong(3, rows.getLong("timestamp_seconds"));
                insert.setInt(4, rows.getInt("timestamp_nanos"));
                insert.setString(5, rows.getString("source_ip"));
                insert.setString(6, rows.getString("destination_ip"));
                insert.setString(7, rows.getString("rule_id"));
                insert.setString(8, rows.getString("rule_name"));
                insert.setString(9, rows.getString("severity"));
                insert.setString(10, rows.getString("description"));
                insert.setString(11, rows.getString("evidence"));
                insert.setString(12, rows.getString("status"));
                insert.setLong(13, rows.getLong("created_at_epoch_ms"));
                insert.addBatch();
                if (++pending == 500) {
                    executeBatch(insert, "intrusion alerts", batchEndId);
                    pending = 0;
                }
            }
            if (pending > 0) {
                executeBatch(insert, "intrusion alerts", batchEndId);
            }
        }
    }

    private static Map<String, RuleConfigRow> migrateRuleConfigs(
            Connection source, Connection destination) throws SQLException {
        Map<String, RuleConfigRow> rows = new LinkedHashMap<>();
        try (PreparedStatement read = source.prepareStatement("""
                     SELECT rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms
                     FROM detection_rule_configs ORDER BY rule_id
                     """);
             ResultSet result = read.executeQuery();
             PreparedStatement upsert = destination.prepareStatement("""
                     INSERT INTO detection_rule_configs(
                         rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms
                     ) VALUES (?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                         threshold = VALUES(threshold),
                         window_seconds = VALUES(window_seconds),
                         enabled = VALUES(enabled),
                         updated_at_epoch_ms = VALUES(updated_at_epoch_ms)
                     """)) {
            while (result.next()) {
                String ruleId = result.getString("rule_id");
                RuleConfigRow row = new RuleConfigRow(
                        result.getLong("threshold"),
                        result.getLong("window_seconds"),
                        result.getInt("enabled"),
                        result.getLong("updated_at_epoch_ms"));
                rows.put(ruleId, row);
                upsert.setString(1, ruleId);
                upsert.setLong(2, row.threshold());
                upsert.setLong(3, row.windowSeconds());
                upsert.setInt(4, row.enabled());
                upsert.setLong(5, row.updatedAtEpochMs());
                upsert.addBatch();
            }
            try {
                upsert.executeBatch();
            } catch (SQLException exception) {
                throw new SQLException("Unable to migrate detection rule configurations "
                        + rows.keySet(), exception);
            }
        }
        if (!rows.isEmpty()) {
            DetectionRuleSettings loaded = loadMigratedSettings(rows);
            Objects.requireNonNull(loaded, "validated rule settings");
        }
        return rows;
    }

    private static DetectionRuleSettings loadMigratedSettings(Map<String, RuleConfigRow> rows)
            throws SQLException {
        if (rows.size() != 3 || !rows.keySet().containsAll(
                java.util.List.of("PORT_SCAN", "SYN_RATE", "ICMP_RATE"))) {
            throw new SQLException("SQLite source has incomplete detection rule configuration");
        }
        RuleConfigRow portScan = rows.get("PORT_SCAN");
        RuleConfigRow syn = rows.get("SYN_RATE");
        RuleConfigRow icmp = rows.get("ICMP_RATE");
        if (portScan.windowSeconds() != syn.windowSeconds()
                || portScan.windowSeconds() != icmp.windowSeconds()) {
            throw new SQLException("SQLite detection rules do not share one observation window");
        }
        try {
            return new DetectionRuleSettings(
                    portScan.threshold(), syn.threshold(), icmp.threshold(),
                    portScan.windowSeconds(), enabled(portScan), enabled(syn), enabled(icmp));
        } catch (IllegalArgumentException exception) {
            throw new SQLException("SQLite source has invalid detection rule configuration", exception);
        }
    }

    private static boolean enabled(RuleConfigRow row) throws SQLException {
        if (row.enabled() != 0 && row.enabled() != 1) {
            throw new SQLException("SQLite source has an invalid rule enabled flag");
        }
        return row.enabled() == 1;
    }

    private static void verifyRuleConfigs(Connection destination, Map<String, RuleConfigRow> expected)
            throws SQLException {
        try (PreparedStatement statement = destination.prepareStatement("""
                SELECT threshold, window_seconds, enabled, updated_at_epoch_ms
                FROM detection_rule_configs WHERE rule_id = ?
                """)) {
            for (Map.Entry<String, RuleConfigRow> entry : expected.entrySet()) {
                statement.setString(1, entry.getKey());
                try (ResultSet result = statement.executeQuery()) {
                    RuleConfigRow row = entry.getValue();
                    if (!result.next()
                            || result.getLong("threshold") != row.threshold()
                            || result.getLong("window_seconds") != row.windowSeconds()
                            || result.getInt("enabled") != row.enabled()
                            || result.getLong("updated_at_epoch_ms") != row.updatedAtEpochMs()) {
                        throw new SQLException("Detection rule configuration did not verify: " + entry.getKey());
                    }
                }
            }
        }
    }

    private static MigrationResult findCompletedMigration(
            Connection destination, String key, Path sourcePath, SourceCounts counts) throws SQLException {
        try (PreparedStatement statement = destination.prepareStatement("""
                SELECT source_sessions, source_alerts, source_rule_configs
                FROM sentinel_data_migrations WHERE migration_key = ?
                """)) {
            statement.setString(1, key);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                if (result.getLong(1) != counts.sessions()
                        || result.getLong(2) != counts.alerts()
                        || result.getLong(3) != counts.ruleConfigs()) {
                    throw new SQLException(
                            "SQLite source record counts changed after its completed migration");
                }
                return new MigrationResult(
                        sourcePath, counts.sessions(), counts.alerts(), counts.ruleConfigs(), true);
            }
        }
    }

    private static void recordMigration(
            Connection destination, String key, Path sourcePath, SourceCounts counts) throws SQLException {
        try (PreparedStatement statement = destination.prepareStatement("""
                INSERT INTO sentinel_data_migrations(
                    migration_key, source_path, source_sessions, source_alerts,
                    source_rule_configs, completed_at_epoch_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, key);
            statement.setString(2, sourcePath.toString());
            statement.setLong(3, counts.sessions());
            statement.setLong(4, counts.alerts());
            statement.setLong(5, counts.ruleConfigs());
            statement.setLong(6, System.currentTimeMillis());
            statement.executeUpdate();
        }
    }

    private static String migrationKey(Path sourcePath) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(sourcePath.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable in this Java runtime", exception);
        }
    }

    private static long count(Connection connection, String table) throws SQLException {
        if (!java.util.Set.of("import_sessions", "intrusion_alerts", "detection_rule_configs")
                .contains(table)) {
            throw new IllegalArgumentException("Unexpected table name");
        }
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            if (!result.next()) {
                throw new SQLException("Unable to count rows in " + table);
            }
            return result.getLong(1);
        }
    }

    private static void verifyCount(
            Connection destination, String table, long initialCount, long expectedNewRows)
            throws SQLException {
        long actualNewRows = count(destination, table) - initialCount;
        if (actualNewRows != expectedNewRows) {
            throw new SQLException("Row count mismatch for " + table + ": expected "
                    + expectedNewRows + " migrated rows but observed " + actualNewRows);
        }
    }

    private static void setNullableLong(
            PreparedStatement statement, int parameter, ResultSet result, String column) throws SQLException {
        long value = result.getLong(column);
        if (result.wasNull()) {
            statement.setNull(parameter, java.sql.Types.BIGINT);
        } else {
            statement.setLong(parameter, value);
        }
    }

    private static void executeBatch(PreparedStatement statement, String table, String lastId)
            throws SQLException {
        try {
            statement.executeBatch();
        } catch (SQLException exception) {
            throw new SQLException(
                    "Unable to migrate " + table + " batch ending at source ID " + lastId, exception);
        }
    }

    private static void rollback(Connection connection, Throwable original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    public record MigrationResult(
            Path source,
            long sessions,
            long alerts,
            long ruleConfigs,
            boolean alreadyMigrated) {
    }

    private record SourceCounts(long sessions, long alerts, long ruleConfigs) {
    }

    private record RuleConfigRow(
            long threshold,
            long windowSeconds,
            int enabled,
            long updatedAtEpochMs) {
    }
}
