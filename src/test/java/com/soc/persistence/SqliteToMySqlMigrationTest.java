package com.soc.persistence;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SqliteToMySqlMigrationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void missingSourceIsRejectedBeforeAttemptingMySqlConnection() {
        MySqlDatabase target = new MySqlDatabase(new MySqlDatabaseConfig(
                "jdbc:mysql://127.0.0.1:1/sentinel_noc_test",
                "sentinel_app",
                UUID.randomUUID().toString()));

        assertThrows(PersistenceException.class,
                () -> new SqliteToMySqlMigration(target)
                        .migrate(temporaryDirectory.resolve("missing.db")));
    }

    @Test
    void connectionFailureIsReportedWithoutExposingThePassword() {
        String password = UUID.randomUUID().toString();
        MySqlDatabase unavailable = new MySqlDatabase(new MySqlDatabaseConfig(
                "jdbc:mysql://127.0.0.1:1/sentinel_noc_test?connectTimeout=1000&socketTimeout=1000",
                "sentinel_app",
                password));

        PersistenceException failure =
                assertThrows(PersistenceException.class, unavailable::initialize);

        assertFalse(failure.getMessage().contains(password));
    }

    @Test
    void opensExistingSqliteSourceInReadOnlyMode() throws Exception {
        Path sourceFile = temporaryDirectory.resolve("read-only-source.db");
        SqliteDatabase source = new SqliteDatabase(sourceFile);
        source.initialize();
        long bytesBefore = java.nio.file.Files.size(sourceFile);

        try (Connection connection = SqliteToMySqlMigration.openReadOnlySource(sourceFile);
             Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class,
                    () -> statement.execute("CREATE TABLE should_not_be_added(id INTEGER PRIMARY KEY)"));
        }

        assertEquals(bytesBefore, java.nio.file.Files.size(sourceFile));
        assertEquals(SqliteDatabase.SCHEMA_VERSION, source.schemaVersion());
    }
}
