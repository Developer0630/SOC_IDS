package com.soc.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;

public final class SqliteDatabase {
    public static final int SCHEMA_VERSION = 1;
    private static final Logger LOGGER = LoggerFactory.getLogger(SqliteDatabase.class);
    private final Path databasePath;

    public SqliteDatabase(Path databasePath) {
        this.databasePath = Objects.requireNonNull(databasePath, "databasePath")
                .toAbsolutePath().normalize();
    }

    public static SqliteDatabase forCurrentUser() {
        String configuredPath = System.getProperty("sentinel.db.path");
        if (configuredPath != null && !configuredPath.isBlank()) {
            return new SqliteDatabase(Path.of(configuredPath));
        }
        String localAppData = System.getenv("LOCALAPPDATA");
        Path appData = localAppData == null || localAppData.isBlank()
                ? Path.of(System.getProperty("user.home"), ".local", "share")
                : Path.of(localAppData);
        return new SqliteDatabase(appData.resolve("SentinelNOC").resolve("sentinel_noc.db"));
    }

    public Path databasePath() {
        return databasePath;
    }

    public int schemaVersion() {
        try (Connection connection = openConnection()) {
            return readSchemaVersion(connection);
        } catch (SQLException exception) {
            throw new PersistenceException("Unable to read database schema version", exception);
        }
    }

    public void initialize() {
        try {
            Files.createDirectories(databasePath.getParent());
            try (Connection connection = openConnection()) {
                connection.setAutoCommit(false);
                try {
                    int currentVersion = readSchemaVersion(connection);
                    if (currentVersion > SCHEMA_VERSION) {
                        throw new SQLException("Database schema version " + currentVersion
                                + " is newer than supported version " + SCHEMA_VERSION);
                    }
                    if (currentVersion == 0) {
                        createVersionOneSchema(connection);
                        setSchemaVersion(connection, 1);
                    }
                    connection.commit();
                    LOGGER.info("SQLite database initialized at '{}' (schema version {})",
                            databasePath, SCHEMA_VERSION);
                } catch (SQLException | RuntimeException exception) {
                    rollback(connection, exception);
                    throw exception;
                }
            }
        } catch (IOException | SQLException | RuntimeException exception) {
            if (exception instanceof PersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new PersistenceException(
                    "Unable to initialize Sentinel NOC database at " + databasePath, exception);
        }
    }

    Connection openConnection() throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
        boolean configured = false;
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
            configured = true;
        } finally {
            if (!configured) {
                connection.close();
            }
        }
        return connection;
    }

    private static int readSchemaVersion(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             var result = statement.executeQuery("PRAGMA user_version")) {
            if (!result.next()) {
                throw new SQLException("SQLite did not return a schema version");
            }
            return result.getInt(1);
        }
    }

    private static void setSchemaVersion(Connection connection, int version) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA user_version = " + version);
        }
    }

    private static void createVersionOneSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE import_sessions (
                        id TEXT PRIMARY KEY NOT NULL,
                        file_name TEXT NOT NULL,
                        started_at_epoch_ms INTEGER NOT NULL,
                        completed_at_epoch_ms INTEGER,
                        status TEXT NOT NULL CHECK (status IN
                            ('RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'INTERRUPTED')),
                        total_records INTEGER NOT NULL DEFAULT 0 CHECK (total_records >= 0),
                        parsed_packets INTEGER NOT NULL DEFAULT 0 CHECK (parsed_packets >= 0),
                        unsupported_packets INTEGER NOT NULL DEFAULT 0 CHECK (unsupported_packets >= 0),
                        malformed_packets INTEGER NOT NULL DEFAULT 0 CHECK (malformed_packets >= 0),
                        alerts_created INTEGER NOT NULL DEFAULT 0 CHECK (alerts_created >= 0),
                        error_message TEXT
                    )
                    """);
            statement.execute("""
                    CREATE TABLE intrusion_alerts (
                        id TEXT PRIMARY KEY NOT NULL,
                        import_session_id TEXT NOT NULL REFERENCES import_sessions(id) ON DELETE RESTRICT,
                        timestamp_seconds INTEGER NOT NULL,
                        timestamp_nanos INTEGER NOT NULL CHECK (timestamp_nanos BETWEEN 0 AND 999999999),
                        source_ip TEXT,
                        destination_ip TEXT,
                        rule_id TEXT NOT NULL,
                        rule_name TEXT NOT NULL,
                        severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                        description TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status = 'NEW'),
                        created_at_epoch_ms INTEGER NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX idx_alerts_timestamp ON intrusion_alerts(timestamp_seconds DESC, timestamp_nanos DESC)");
            statement.execute("CREATE INDEX idx_alerts_import_timestamp ON intrusion_alerts(import_session_id, timestamp_seconds DESC, timestamp_nanos DESC)");
            statement.execute("CREATE INDEX idx_alerts_rule ON intrusion_alerts(rule_id)");
            statement.execute("CREATE INDEX idx_alerts_severity ON intrusion_alerts(severity)");
            statement.execute("""
                    CREATE TABLE detection_rule_configs (
                        rule_id TEXT PRIMARY KEY NOT NULL CHECK (rule_id IN
                            ('PORT_SCAN', 'SYN_RATE', 'ICMP_RATE')),
                        threshold INTEGER NOT NULL CHECK (threshold > 0),
                        window_seconds INTEGER NOT NULL CHECK (window_seconds BETWEEN 1 AND 3600),
                        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                        updated_at_epoch_ms INTEGER NOT NULL
                    )
                    """);
        }
    }

    private static void rollback(Connection connection, Throwable original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
