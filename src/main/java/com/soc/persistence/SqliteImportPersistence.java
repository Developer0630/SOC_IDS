package com.soc.persistence;

import java.util.Objects;
import java.util.Optional;

public final class SqliteImportPersistence extends JdbcImportPersistence {
    private static final String RULE_UPSERT_SQL = """
            INSERT INTO detection_rule_configs(rule_id, threshold, window_seconds, enabled, updated_at_epoch_ms)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                threshold = excluded.threshold,
                window_seconds = excluded.window_seconds,
                enabled = excluded.enabled,
                updated_at_epoch_ms = excluded.updated_at_epoch_ms
            """;

    public SqliteImportPersistence(SqliteDatabase database) {
        super(
                Objects.requireNonNull(database, "database")::openConnection,
                "SQLite: " + database.databasePath(),
                Optional.of(database.databasePath()));
    }

    @Override
    protected String ruleUpsertSql() {
        return RULE_UPSERT_SQL;
    }
}
