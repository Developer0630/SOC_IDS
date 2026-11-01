package com.soc.persistence;

import com.soc.detection.DetectionRuleSettings;
import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.RiskLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

abstract class JdbcImportPersistence implements ImportPersistence {
    public static final int DEFAULT_QUERY_LIMIT = 500;
    private static final Logger LOGGER = LoggerFactory.getLogger(JdbcImportPersistence.class);
    private final SqlConnectionProvider connectionProvider;
    private final String storageDescription;
    private final Optional<java.nio.file.Path> databasePath;

    protected JdbcImportPersistence(
            SqlConnectionProvider connectionProvider,
            String storageDescription,
            Optional<java.nio.file.Path> databasePath) {
        this.connectionProvider = Objects.requireNonNull(connectionProvider, "connectionProvider");
        this.storageDescription = Objects.requireNonNull(storageDescription, "storageDescription");
        this.databasePath = Objects.requireNonNull(databasePath, "databasePath");
    }

    @Override
    public final Optional<java.nio.file.Path> databasePath() {
        return databasePath;
    }

    @Override
    public final String storageDescription() {
        return storageDescription;
    }

    protected abstract String ruleUpsertSql();

    @Override
    public void startImport(ImportSession session) {
        Objects.requireNonNull(session, "session");
        if (session.status() != ImportSessionStatus.RUNNING) {
            throw new IllegalArgumentException("New import session must be RUNNING");
        }
        execute("Unable to create import history", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO import_sessions (
                        id, file_name, started_at_epoch_ms, status, total_records, parsed_packets,
                        unsupported_packets, malformed_packets, alerts_created, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                bindSession(statement, session);
                statement.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void completeImport(ImportSession session, List<IntrusionAlert> alerts) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(alerts, "alerts");
        if (session.status() != ImportSessionStatus.COMPLETED || session.completedAt().isEmpty()) {
            throw new IllegalArgumentException("Completed import session is required");
        }
        if (session.alertsCreated() < alerts.size()
                || alerts.stream().anyMatch(alert -> !alert.importId().equals(session.id()))) {
            throw new IllegalArgumentException("Alert batch does not match the import session summary");
        }
        execute("Unable to save completed import and alerts", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO intrusion_alerts (
                        id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                        destination_ip, rule_id, rule_name, severity, description, evidence, status,
                        created_at_epoch_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                for (IntrusionAlert alert : alerts) {
                    bindAlert(statement, alert);
                    statement.addBatch();
                }
                statement.executeBatch();
            }
            updateSession(connection, session);
            return null;
        });
        LOGGER.info("Persisted import session {} with {} alerts", session.id(), alerts.size());
    }

    @Override
    public void finishImport(ImportSession session) {
        Objects.requireNonNull(session, "session");
        if (session.status() == ImportSessionStatus.RUNNING
                || session.status() == ImportSessionStatus.COMPLETED) {
            throw new IllegalArgumentException("A failed or cancelled terminal status is required");
        }
        execute("Unable to update import session status", connection -> {
            updateSession(connection, session);
            return null;
        });
    }

    @Override
    public List<ImportSession> recentImports(int limit) {
        validateLimit(limit);
        return execute("Unable to query import history", connection -> {
            List<ImportSession> sessions = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT id, file_name, started_at_epoch_ms, completed_at_epoch_ms, status,
                           total_records, parsed_packets, unsupported_packets, malformed_packets,
                           alerts_created, error_message
                    FROM import_sessions
                    ORDER BY started_at_epoch_ms DESC, id DESC
                    LIMIT ?
                    """)) {
                statement.setInt(1, limit);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        sessions.add(readSession(result));
                    }
                }
            }
            return List.copyOf(sessions);
        });
    }

    @Override
    public void markRunningImportsInterrupted() {
        execute("Unable to recover unfinished import sessions", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE import_sessions
                    SET status = 'INTERRUPTED', completed_at_epoch_ms = ?, error_message = ?
                    WHERE status = 'RUNNING'
                    """)) {
                statement.setLong(1, System.currentTimeMillis());
                statement.setString(2, "Application stopped before this import completed.");
                int count = statement.executeUpdate();
                if (count > 0) {
                    LOGGER.warn("Marked {} unfinished import session(s) as interrupted", count);
                }
            }
            return null;
        });
    }

    @Override
    public void saveAll(List<IntrusionAlert> alerts) {
        Objects.requireNonNull(alerts, "alerts");
        execute("Unable to save alerts", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO intrusion_alerts (
                        id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                        destination_ip, rule_id, rule_name, severity, description, evidence, status,
                        created_at_epoch_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                for (IntrusionAlert alert : alerts) {
                    bindAlert(statement, alert);
                    statement.addBatch();
                }
                statement.executeBatch();
            }
            return null;
        });
    }

    @Override
    public List<IntrusionAlert> findAll() {
        return findRecent(DEFAULT_QUERY_LIMIT);
    }

    @Override
    public List<IntrusionAlert> findRecent(int limit) {
        validateLimit(limit);
        return queryAlerts("""
                SELECT id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                       destination_ip, rule_id, rule_name, severity, description, evidence, status
                FROM intrusion_alerts
                ORDER BY timestamp_seconds DESC, timestamp_nanos DESC, id DESC
                LIMIT ?
                """, statement -> statement.setInt(1, limit));
    }

    @Override
    public List<IntrusionAlert> findByImport(UUID importId, int limit) {
        Objects.requireNonNull(importId, "importId");
        validateLimit(limit);
        return queryAlerts("""
                SELECT id, import_session_id, timestamp_seconds, timestamp_nanos, source_ip,
                       destination_ip, rule_id, rule_name, severity, description, evidence, status
                FROM intrusion_alerts
                WHERE import_session_id = ?
                ORDER BY timestamp_seconds DESC, timestamp_nanos DESC, id DESC
                LIMIT ?
                """, statement -> {
            statement.setString(1, importId.toString());
            statement.setInt(2, limit);
        });
    }

    @Override
    public long countAlerts() {
        return count("SELECT COUNT(*) FROM intrusion_alerts");
    }

    @Override
    public long countCriticalAlerts() {
        return execute("Unable to count critical alerts", connection -> {
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "SELECT COUNT(*) FROM intrusion_alerts WHERE severity = 'CRITICAL'")) {
                return result.next() ? result.getLong(1) : 0L;
            }
        });
    }

    @Override
    public DetectionRuleSettings loadOrCreateRuleSettings() {
        return execute("Unable to load detection rule configuration", connection -> {
            Map<String, RuleRow> rows = new HashMap<>();
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("""
                         SELECT rule_id, threshold, window_seconds, enabled
                         FROM detection_rule_configs
                         """)) {
                while (result.next()) {
                    rows.put(result.getString("rule_id"),
                            new RuleRow(result.getLong("threshold"),
                                    result.getLong("window_seconds"),
                                    result.getInt("enabled")));
                }
            }
            if (rows.isEmpty()) {
                DetectionRuleSettings defaults = DetectionRuleSettings.defaults();
                saveRuleSettings(connection, defaults);
                return defaults;
            }
            if (rows.size() != 3 || !rows.keySet().containsAll(
                    List.of("PORT_SCAN", "SYN_RATE", "ICMP_RATE"))) {
                throw new SQLException("Detection rule configuration is incomplete");
            }
            RuleRow portScan = rows.get("PORT_SCAN");
            RuleRow syn = rows.get("SYN_RATE");
            RuleRow icmp = rows.get("ICMP_RATE");
            if (portScan.windowSeconds() != syn.windowSeconds()
                    || portScan.windowSeconds() != icmp.windowSeconds()) {
                throw new SQLException("Stored detection rules do not share one observation window");
            }
            return new DetectionRuleSettings(
                    portScan.threshold(), syn.threshold(), icmp.threshold(),
                    portScan.windowSeconds(), enabled(portScan), enabled(syn), enabled(icmp));
        });
    }

    @Override
    public void saveRuleSettings(DetectionRuleSettings settings) {
        Objects.requireNonNull(settings, "settings");
        execute("Unable to save detection rule configuration", connection -> {
            saveRuleSettings(connection, settings);
            return null;
        });
    }

    private List<IntrusionAlert> queryAlerts(String sql, StatementBinder binder) {
        return execute("Unable to query alerts", connection -> {
            List<IntrusionAlert> alerts = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                binder.bind(statement);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        alerts.add(readAlert(result));
                    }
                }
            }
            return List.copyOf(alerts);
        });
    }

    private long count(String sql) {
        return execute("Unable to count alerts", connection -> {
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(sql)) {
                return result.next() ? result.getLong(1) : 0L;
            }
        });
    }

    private void saveRuleSettings(Connection connection, DetectionRuleSettings settings)
            throws SQLException {
        long updatedAt = System.currentTimeMillis();
        try (PreparedStatement statement = connection.prepareStatement(ruleUpsertSql())) {
            bindRule(statement, "PORT_SCAN", settings.portScanThreshold(),
                    settings.observationWindowSeconds(), settings.portScanEnabled(), updatedAt);
            statement.addBatch();
            bindRule(statement, "SYN_RATE", settings.synThreshold(),
                    settings.observationWindowSeconds(), settings.synEnabled(), updatedAt);
            statement.addBatch();
            bindRule(statement, "ICMP_RATE", settings.icmpThreshold(),
                    settings.observationWindowSeconds(), settings.icmpEnabled(), updatedAt);
            statement.addBatch();
            statement.executeBatch();
        }
    }

    private static void bindRule(
            PreparedStatement statement, String id, long threshold, long window, boolean enabled, long updatedAt)
            throws SQLException {
        statement.setString(1, id);
        statement.setLong(2, threshold);
        statement.setLong(3, window);
        statement.setInt(4, enabled ? 1 : 0);
        statement.setLong(5, updatedAt);
    }

    private static boolean enabled(RuleRow row) throws SQLException {
        if (row.enabled() != 0 && row.enabled() != 1) {
            throw new SQLException("Stored detection rule enabled flag is invalid");
        }
        return row.enabled() == 1;
    }

    private static void bindSession(PreparedStatement statement, ImportSession session) throws SQLException {
        statement.setString(1, session.id().toString());
        statement.setString(2, session.fileName());
        statement.setLong(3, session.startedAt().toEpochMilli());
        statement.setString(4, session.status().name());
        statement.setLong(5, session.totalRecords());
        statement.setLong(6, session.parsedPackets());
        statement.setLong(7, session.unsupportedPackets());
        statement.setLong(8, session.malformedPackets());
        statement.setLong(9, session.alertsCreated());
        setOptionalString(statement, 10, session.errorMessage());
    }

    private static void updateSession(Connection connection, ImportSession session) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE import_sessions
                SET completed_at_epoch_ms = ?, status = ?, total_records = ?, parsed_packets = ?,
                    unsupported_packets = ?, malformed_packets = ?, alerts_created = ?, error_message = ?
                WHERE id = ? AND status = 'RUNNING'
                """)) {
            statement.setLong(1, session.completedAt().orElseThrow().toEpochMilli());
            statement.setString(2, session.status().name());
            statement.setLong(3, session.totalRecords());
            statement.setLong(4, session.parsedPackets());
            statement.setLong(5, session.unsupportedPackets());
            statement.setLong(6, session.malformedPackets());
            statement.setLong(7, session.alertsCreated());
            setOptionalString(statement, 8, session.errorMessage());
            statement.setString(9, session.id().toString());
            if (statement.executeUpdate() != 1) {
                throw new SQLException("Import session is missing or is no longer RUNNING");
            }
        }
    }

    private static void bindAlert(PreparedStatement statement, IntrusionAlert alert) throws SQLException {
        statement.setString(1, alert.id().toString());
        statement.setString(2, alert.importId().toString());
        statement.setLong(3, alert.timestamp().getEpochSecond());
        statement.setInt(4, alert.timestamp().getNano());
        setOptionalString(statement, 5, alert.sourceAddress());
        setOptionalString(statement, 6, alert.destinationAddress());
        statement.setString(7, alert.ruleId());
        statement.setString(8, alert.ruleName());
        statement.setString(9, alert.severity().name());
        statement.setString(10, alert.description());
        statement.setString(11, alert.evidence());
        statement.setString(12, alert.status().name());
        statement.setLong(13, System.currentTimeMillis());
    }

    private static ImportSession readSession(ResultSet result) throws SQLException {
        long completed = result.getLong("completed_at_epoch_ms");
        Optional<Instant> completedAt = result.wasNull()
                ? Optional.empty()
                : Optional.of(Instant.ofEpochMilli(completed));
        String error = result.getString("error_message");
        return new ImportSession(
                UUID.fromString(result.getString("id")),
                result.getString("file_name"),
                Instant.ofEpochMilli(result.getLong("started_at_epoch_ms")),
                completedAt,
                ImportSessionStatus.valueOf(result.getString("status")),
                result.getLong("total_records"),
                result.getLong("parsed_packets"),
                result.getLong("unsupported_packets"),
                result.getLong("malformed_packets"),
                result.getLong("alerts_created"),
                Optional.ofNullable(error));
    }

    private static IntrusionAlert readAlert(ResultSet result) throws SQLException {
        Instant timestamp = Instant.ofEpochSecond(
                result.getLong("timestamp_seconds"), result.getInt("timestamp_nanos"));
        return new IntrusionAlert(
                UUID.fromString(result.getString("id")),
                timestamp,
                Optional.ofNullable(result.getString("source_ip")),
                Optional.ofNullable(result.getString("destination_ip")),
                result.getString("rule_id"),
                result.getString("rule_name"),
                RiskLevel.valueOf(result.getString("severity")),
                result.getString("description"),
                result.getString("evidence"),
                AlertStatus.valueOf(result.getString("status")),
                UUID.fromString(result.getString("import_session_id")));
    }

    private static void setOptionalString(
            PreparedStatement statement, int parameter, Optional<String> value) throws SQLException {
        if (value.isPresent()) {
            statement.setString(parameter, value.get());
        } else {
            statement.setNull(parameter, java.sql.Types.VARCHAR);
        }
    }

    private static void validateLimit(int limit) {
        if (limit <= 0 || limit > 1000) {
            throw new IllegalArgumentException("Query limit must be between 1 and 1000");
        }
    }

    private <T> T execute(String failureMessage, SqlWork<T> work) {
        try (Connection connection = connectionProvider.openConnection()) {
            connection.setAutoCommit(false);
            try {
                T result = work.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException exception) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    exception.addSuppressed(rollbackFailure);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new PersistenceException(failureMessage, exception);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run(Connection connection) throws SQLException;
    }

    @FunctionalInterface
    private interface StatementBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    private record RuleRow(long threshold, long windowSeconds, int enabled) {
    }

    @FunctionalInterface
    protected interface SqlConnectionProvider {
        Connection openConnection() throws SQLException;
    }
}
