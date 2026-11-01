package com.soc.persistence;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MySqlDatabaseConfigTest {
    @Test
    void acceptsSeparateCredentialsAndRejectsRootOrCredentialsInUrl() {
        MySqlDatabaseConfig config = new MySqlDatabaseConfig(
                "jdbc:mysql://localhost:3306/sentinel_noc", "sentinel_app", UUID.randomUUID().toString());

        assertEquals("sentinel_app", config.username());
        assertThrows(IllegalArgumentException.class, () -> new MySqlDatabaseConfig(
                "jdbc:mysql://localhost:3306/sentinel_noc", "root", UUID.randomUUID().toString()));
        assertThrows(IllegalArgumentException.class, () -> new MySqlDatabaseConfig(
                "jdbc:mysql://localhost:3306/sentinel_noc?password=secret",
                "sentinel_app", UUID.randomUUID().toString()));
        assertThrows(IllegalArgumentException.class, () -> new MySqlDatabaseConfig(
                "jdbc:mysql://localhost:3306", "sentinel_app", UUID.randomUUID().toString()));
    }

    @Test
    void rejectsBlankPassword() {
        assertThrows(IllegalArgumentException.class, () -> new MySqlDatabaseConfig(
                "jdbc:mysql://localhost:3306/sentinel_noc", "sentinel_app", " "));
    }
}
