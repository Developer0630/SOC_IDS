package com.soc.persistence;

import java.util.Locale;
import java.util.Objects;

public record MySqlDatabaseConfig(String jdbcUrl, String username, String password) {
    public MySqlDatabaseConfig {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        jdbcUrl = jdbcUrl.trim();
        username = username.trim();
        if (!jdbcUrl.startsWith("jdbc:mysql://")) {
            throw new IllegalArgumentException("Database URL must use the jdbc:mysql scheme");
        }
        String authorityAndPath = jdbcUrl.substring("jdbc:mysql://".length());
        int databaseSeparator = authorityAndPath.indexOf('/');
        if (databaseSeparator < 1 || databaseSeparator == authorityAndPath.length() - 1
                || authorityAndPath.charAt(databaseSeparator + 1) == '?') {
            throw new IllegalArgumentException("MySQL JDBC URL must include a database name");
        }
        if (username.isBlank() || username.equalsIgnoreCase("root")) {
            throw new IllegalArgumentException("Configure a non-root MySQL application user");
        }
        if (password.isBlank()) {
            throw new IllegalArgumentException("SENTINEL_DB_PASSWORD must be configured");
        }
        String normalizedUrl = jdbcUrl.toLowerCase(Locale.ROOT);
        if (normalizedUrl.contains("password=") || normalizedUrl.contains("user=")
                || normalizedUrl.matches("jdbc:mysql://[^/]*@.*")) {
            throw new IllegalArgumentException(
                    "Do not include credentials in the JDBC URL; use separate environment variables");
        }
    }

    public static MySqlDatabaseConfig fromEnvironment() {
        String url = environmentOrDefault(
                "SENTINEL_DB_URL",
                "jdbc:mysql://localhost:3306/sentinel_noc?connectTimeout=5000&socketTimeout=10000&tcpKeepAlive=true&serverTimezone=UTC");
        String username = environmentOrDefault("SENTINEL_DB_USER", "sentinel_app");
        String password = System.getenv("SENTINEL_DB_PASSWORD");
        if (password == null || password.isBlank()) {
            throw new PersistenceException(
                    "MySQL is selected, but SENTINEL_DB_PASSWORD is not configured",
                    new IllegalStateException("Required MySQL password environment variable is missing"));
        }
        try {
            return new MySqlDatabaseConfig(url, username, password);
        } catch (IllegalArgumentException exception) {
            throw new PersistenceException(
                    "Invalid MySQL connection configuration; check SENTINEL_DB_URL and SENTINEL_DB_USER",
                    exception);
        }
    }

    @Override
    public String toString() {
        return "MySqlDatabaseConfig[jdbcUrl=" + jdbcUrl + ", username=" + username + ", password=<redacted>]";
    }

    private static String environmentOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value.trim();
    }
}
