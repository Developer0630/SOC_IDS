package com.soc.persistence;

import java.util.Objects;
import java.util.Optional;

public final class MySqlImportPersistence extends JdbcImportPersistence {
    private static final String RULE_UPSERT_SQL = """
            INSERT INTO detection_rule_configs(rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                threshold = VALUES(threshold),
                window_seconds = VALUES(window_seconds),
                enabled = VALUES(enabled),
                updated_at_epoch_ms = VALUES(updated_at_epoch_ms)
            """;

    public MySqlImportPersistence(MySqlDatabase database) {
        super(
                Objects.requireNonNull(database, "database")::openConnection,
                "MySQL: " + database.databaseName(),
                Optional.empty());
    }

    @Override
    protected String ruleUpsertSql() {
        return RULE_UPSERT_SQL;
    }
}
