package com.soc.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.Properties;

public final class MySqlDatabase {
    public static final int SCHEMA_VERSION = 1;
    private static final Logger LOGGER = LoggerFactory.getLogger(MySqlDatabase.class);
    private static final String MIGRATION_LOCK = "sentinel_noc_schema_migration";
    private final MySqlDatabaseConfig config;

    public MySqlDatabase(MySqlDatabaseConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    public static MySqlDatabase fromEnvironment() {
        return new MySqlDatabase(MySqlDatabaseConfig.fromEnvironment());
    }

    public String databaseName() {
        String path = config.jdbcUrl().substring("jdbc:mysql://".length());
        int slash = path.indexOf('/');
        if (slash < 0 || slash == path.length() - 1) {
            return "configured database";
        }
        String name = path.substring(slash + 1);
        int query = name.indexOf('?');
        return query < 0 ? name : name.substring(0, query);
    }

    public int schemaVersion() {
        try (Connection connection = openConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COALESCE(MAX(version), 0) FROM schema_migrations");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("MySQL did not return a schema version");
            }
            return result.getInt(1);
        } catch (SQLException exception) {
            throw new PersistenceException("Unable to read MySQL schema version", exception);
        }
    }

    public void initialize() {
        try (Connection connection = openConnection()) {
            createMigrationTables(connection);
            acquireMigrationLock(connection);
            try {
                int currentVersion = readSchemaVersion(connection);
                if (currentVersion > SCHEMA_VERSION) {
                    throw new SQLException("Database schema version " + currentVersion
                            + " is newer than supported version " + SCHEMA_VERSION);
                }
                if (currentVersion < 1) {
                    createVersionOneSchema(connection);
                    recordSchemaVersion(connection, 1);
                }
                LOGGER.info("MySQL database '{}' initialized (schema version {})",
                        databaseName(), SCHEMA_VERSION);
            } finally {
                releaseMigrationLock(connection);
            }
        } catch (SQLException exception) {
            throw new PersistenceException(
                    "Unable to initialize MySQL database '" + databaseName()
                            + "'. Check that the server, database, credentials, and schema privileges are available.",
                    exception);
        }
    }

    Connection openConnection() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", config.username());
        properties.setProperty("password", config.password());
        properties.setProperty("connectTimeout", "5000");
        properties.setProperty("socketTimeout", "10000");
        return DriverManager.getConnection(config.jdbcUrl(), properties);
    }

    private static void createMigrationTables(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INT NOT NULL PRIMARY KEY,
                        applied_at_epoch_ms BIGINT NOT NULL
                    ) ENGINE=InnoDB
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS sentinel_data_migrations (
                        migration_key CHAR(64) NOT NULL PRIMARY KEY,
                        source_path VARCHAR(2048) NOT NULL,
                        source_sessions BIGINT NOT NULL,
                        source_alerts BIGINT NOT NULL,
                        source_rule_configs BIGINT NOT NULL,
                        completed_at_epoch_ms BIGINT NOT NULL
                    ) ENGINE=InnoDB
                    """);
        }
    }

    private static void acquireMigrationLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT GET_LOCK(?, 10)")) {
            statement.setString(1, MIGRATION_LOCK);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || result.getInt(1) != 1) {
                    throw new SQLException("Could not acquire the schema migration lock within 10 seconds");
                }
            }
        }
    }

    private static void releaseMigrationLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT RELEASE_LOCK(?)")) {
            statement.setString(1, MIGRATION_LOCK);
            try (ResultSet ignored = statement.executeQuery()) {
                if (!ignored.next()) {
                    throw new SQLException("MySQL did not release the schema migration lock");
                }
            }
        }
    }

    private static int readSchemaVersion(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("MySQL did not return a schema version");
            }
            return result.getInt(1);
        }
    }

    private static void createVersionOneSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS import_sessions (
                        id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                        file_name VARCHAR(1024) NOT NULL,
                        started_at_epoch_ms BIGINT NOT NULL,
                        completed_at_epoch_ms BIGINT NULL,
                        status VARCHAR(16) NOT NULL,
                        total_records BIGINT NOT NULL DEFAULT 0,
                        parsed_packets BIGINT NOT NULL DEFAULT 0,
                        unsupported_packets BIGINT NOT NULL DEFAULT 0,
                        malformed_packets BIGINT NOT NULL DEFAULT 0,
                        alerts_created BIGINT NOT NULL DEFAULT 0,
                        error_message TEXT NULL,
                        CONSTRAINT chk_import_status CHECK
                            (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'INTERRUPTED')),
                        CONSTRAINT chk_import_counters CHECK
                            (total_records >= 0 AND parsed_packets >= 0 AND unsupported_packets >= 0
                                AND malformed_packets >= 0 AND alerts_created >= 0)
                    ) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS intrusion_alerts (
                        id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                        import_session_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                        timestamp_seconds BIGINT NOT NULL,
                        timestamp_nanos INT NOT NULL,
                        source_ip VARCHAR(45) NULL,
                        destination_ip VARCHAR(45) NULL,
                        rule_id VARCHAR(64) NOT NULL,
                        rule_name VARCHAR(255) NOT NULL,
                        severity VARCHAR(16) NOT NULL,
                        description TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        status VARCHAR(16) NOT NULL,
                        created_at_epoch_ms BIGINT NOT NULL,
                        INDEX idx_alerts_timestamp (timestamp_seconds, timestamp_nanos, id),
                        INDEX idx_alerts_import_timestamp
                            (import_session_id, timestamp_seconds, timestamp_nanos, id),
                        INDEX idx_alerts_rule (rule_id),
                        INDEX idx_alerts_severity (severity),
                        CONSTRAINT fk_alert_import_session FOREIGN KEY (import_session_id)
                            REFERENCES import_sessions(id) ON DELETE RESTRICT,
                        CONSTRAINT chk_alert_timestamp_nanos CHECK (timestamp_nanos BETWEEN 0 AND 999999999),
                        CONSTRAINT chk_alert_severity CHECK
                            (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                        CONSTRAINT chk_alert_status CHECK (status = 'NEW')
                    ) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS detection_rule_configs (
                        rule_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                        threshold BIGINT NOT NULL,
                        window_seconds BIGINT NOT NULL,
                        enabled TINYINT NOT NULL,
                        updated_at_epoch_ms BIGINT NOT NULL,
                        CONSTRAINT chk_rule_id CHECK
                            (rule_id IN ('PORT_SCAN', 'SYN_RATE', 'ICMP_RATE')),
                        CONSTRAINT chk_rule_threshold CHECK (threshold > 0),
                        CONSTRAINT chk_rule_window CHECK (window_seconds BETWEEN 1 AND 3600),
                        CONSTRAINT chk_rule_enabled CHECK (enabled IN (0, 1))
                    ) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    """);
        }
    }

    private static void recordSchemaVersion(Connection connection, int version) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO schema_migrations(version, applied_at_epoch_ms) VALUES (?, ?)")) {
            statement.setInt(1, version);
            statement.setLong(2, System.currentTimeMillis());
            statement.executeUpdate();
        }
    }
}
