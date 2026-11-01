# Phase 6 — MySQL Persistence Migration

## Scope and status

Phase 6 changes the active application persistence backend from SQLite to MariaDB 10.4.32 using MySQL Connector/J
9.2.0. The PCAP reader/parser,
event-time aggregation, detection rules, suppression behavior, alert retention limit, cancellation behavior, and
JavaFX history queries continue to use the existing `ImportPersistence` contract.

The configured dedicated test database `sentinel_noc_test` was verified through a read-only JDBC connection as
MariaDB `5.5.5-10.4.32-MariaDB` (the compatibility version string returned by this server/driver combination).
The six repository integration tests ran twice against that database, followed by the full 72-test suite with no
failures or skips. This verifies the exercised persistence operations on that local MariaDB server; it does not
verify production deployment, production data migration, or the JavaFX GUI. See the verification section for
commands and reports.

## Architecture

- `JdbcImportPersistence` contains the shared persistence/repository operations and alert/session mapping.
- `SqliteImportPersistence` remains as the SQLite implementation used by the legacy tests and migration source.
- `MySqlImportPersistence` uses MySQL-specific parameterized upsert syntax and a fresh JDBC connection for each
  operation. There is no shared `Connection` and no connection pool; database work remains on existing background
  tasks.
- `PcapImportService` still starts a `RUNNING` session, and successful import writes its alert batch and
  `COMPLETED` state in one transaction. Failed/cancelled imports retain counters and terminal state. Storage errors
  do not become successful imports.
- `MainApp` initializes MySQL before showing the dashboard. Unavailable MySQL, invalid credentials, missing schema,
  or migration/config errors are shown in degraded UI state and disable imports. There is no SQLite or in-memory
  fallback.
- Connection and socket timeout defaults are 5 and 10 seconds. Environment variables can override the JDBC URL,
  user, and password. Credentials are separate from the URL; root is rejected and password values are redacted
  from configuration display.

## MariaDB requirement and database/user setup

Target environment is **MariaDB 10.4.32 supplied by XAMPP**, with MySQL Connector/J 9.2.0 and Java 17. This
driver/server combination has been exercised against MariaDB 10.4.32 using the persistence integration tests.
First edit the password placeholder in
[database/mysql/init.sql](database/mysql/init.sql) in your local
working copy, then execute that script with an administrator account. Do not commit the edited file or configure
Sentinel NOC with `root`.

The script creates database `sentinel_noc`, user `sentinel_app`@`localhost`, and schema-scoped privileges needed
for runtime queries and versioned table creation. It does not create or contain a real credential by default.

Set configuration in PowerShell before starting:

```powershell
$env:SENTINEL_DB_URL = "jdbc:mysql://localhost:3306/sentinel_noc?connectTimeout=5000&socketTimeout=10000&tcpKeepAlive=true&serverTimezone=UTC"
$env:SENTINEL_DB_USER = "sentinel_app"
$env:SENTINEL_DB_PASSWORD = "<your-local-application-password>"
mvn javafx:run
```

`SENTINEL_DB_URL` defaults to the URL above and `SENTINEL_DB_USER` defaults to `sentinel_app`. A non-empty
`SENTINEL_DB_PASSWORD` is required. Override all three for another host or database. Keep secrets in the process
environment or an approved local secret manager, not in source files or command history.

## Schema and schema migration

Schema version is stored in `schema_migrations(version, applied_at_epoch_ms)`. The current schema version is 1.
Startup creates the migration bookkeeping tables, takes a MySQL advisory lock, creates missing v1 tables with
idempotent DDL, then records the version. Existing newer versions are rejected without dropping or resetting data.
MySQL DDL may implicitly commit, so schema DDL is designed to be safely retried rather than described as one
transaction. If startup fails part-way through table creation, correct the MySQL issue and restart; existing rows
are not deleted.

| Table | Contents and constraints |
|---|---|
| `import_sessions` | UUID text primary key, file name, epoch-millisecond start/end, lifecycle status, packet counters, generated-alert count and optional failure message |
| `intrusion_alerts` | Alert UUID primary key, FK to import session, exact PCAP event seconds/nanoseconds, optional IPv4/IPv6 text, rule identity, severity, description, evidence, status and creation time |
| `detection_rule_configs` | Rule ID primary key, positive threshold, shared 1–3,600 second window, enabled flag and update time |
| `schema_migrations` | Applied schema version and time |
| `sentinel_data_migrations` | SQLite-source migration key/path, source row counts and completion time |

InnoDB is used. Tables use `utf8mb4_unicode_ci` (supported by MariaDB 10.4 and MySQL) and ASCII binary collations
for UUIDs and rule IDs. Indexes cover recent event-time order, per-import event-time history, rule ID, and severity.
Evidence and optional values are stored without Java object serialization. Event timestamps remain integer seconds
plus nanoseconds to preserve PCAP event-time precision.

The schema avoids MySQL 8-only collation and descending-index syntax. Integration tests on MariaDB 10.4.32
verified invalid status/rule inserts are rejected, repeated schema initialization preserves rows, rule settings
round-trip through `ON DUPLICATE KEY UPDATE`, and import completion rolls back on constraint failures.
`GET_LOCK`/`RELEASE_LOCK` were exercised by schema initialization. These checks cover the tested XAMPP server
version and do not establish compatibility with every MariaDB/MySQL version.

## SQLite backup and migration

Migration is explicit; application startup never reads the SQLite file or migrates it automatically.

1. Close Sentinel NOC so SQLite has no active writer.
2. Make a separate backup. Prefer SQLite's online backup command, or copy the closed database and its safe backup
   outside the application data directory:

   ```powershell
   sqlite3 C:\path\to\sentinel_noc.db ".backup 'C:\backup\sentinel_noc-before-mysql.db'"
   ```

3. Configure MariaDB and ensure the `sentinel_noc` schema exists.
4. Run the migrator against the original SQLite file (not the backup):

   ```powershell
   mvn "-Dexec.mainClass=com.soc.persistence.SqliteToMySqlMigration" `
       "-Dexec.args=C:\path\to\sentinel_noc.db" exec:java
   ```

The utility rejects missing/empty sources before connecting to MySQL, opens SQLite using the JDBC driver's
read-only mode plus `PRAGMA query_only=ON`, and does not call SQLite schema initialization or write to the source.
It accepts the existing SQLite schema version 1, checks foreign-key integrity, and migrates import sessions,
alerts, and rule configurations. Session/alert IDs,
timestamps, statuses, error messages, counters, and evidence are retained. The source remains in place.

Session and alert rows plus the source migration marker are copied in one MySQL DML transaction. A duplicate-key,
foreign-key, validation, or row-count mismatch rolls back the transaction. Detection configuration is copied in
that same transaction and checked against the source values. Source and destination counts are compared before
commit. A successful migration records a key derived from the canonical SQLite source path. Re-running from that
same path checks the recorded source counts and returns without inserting duplicates. If the source counts changed
after migration, it fails rather than silently proceeding.

After migration, check the CLI report (`sessions`, `alerts`, `ruleConfigs`), then inspect the database:

```sql
SELECT version, applied_at_epoch_ms FROM schema_migrations ORDER BY version;
SELECT COUNT(*) FROM import_sessions;
SELECT COUNT(*) FROM intrusion_alerts;
SELECT rule_id, threshold, window_seconds, enabled FROM detection_rule_configs ORDER BY rule_id;
SELECT source_path, source_sessions, source_alerts, source_rule_configs
FROM sentinel_data_migrations;
```

Keep the SQLite source and backup until the MySQL application and migrated history have been checked. The migration
does not remove or modify SQLite data.

## Automated tests

Existing SQLite and pipeline tests remain in place. `MySqlDatabaseConfigTest` checks configuration validation
without requiring a server. `MySqlImportPersistenceTest` contains server integration coverage for:

- Session, alert, exact evidence/timestamp, and detection-rule round trips across fresh connections.
- Schema reinitialization without data loss, transaction rollback, foreign-key and CHECK constraint enforcement,
  `FAILED`/`CANCELLED`/`INTERRUPTED` session states, and history limits.
- SQLite migration, source preservation, row counts, and idempotent repeat runs.

`SqliteToMySqlMigrationTest` verifies missing-source rejection before a MySQL connection is attempted, and verifies
that a connection error is surfaced without including the configured password in the top-level error message.

To run MariaDB integration tests, configure `SENTINEL_MYSQL_TEST_URL`, `SENTINEL_MYSQL_TEST_USER`, and
`SENTINEL_MYSQL_TEST_PASSWORD`. The URL must target a dedicated database whose name ends in `_test`. Before schema
initialization, the integration tests issue a read-only version query and require MariaDB 10.4.32; a different
server version fails setup explicitly rather than being reported as a passing/skipped test. Without a matching
test URL, JUnit reports the class as skipped; if the URL matches but credentials or the database are invalid, the
test run fails.

Each test removes only sessions/alerts associated with its generated UUIDs and the migration marker for its own
temporary SQLite fixture, then restores the exact detection-rule rows and pre-existing `RUNNING` session states
captured before the test. It does not truncate tables or delete pre-existing rows. Historical test rows that
existed before this cleanup was added are not removed automatically; use a disposable test database and review its
contents before any manual cleanup.

For XAMPP, start MariaDB in the XAMPP Control Panel. Using an administrator session, create a separate test
database and account (choose a local secret without committing it):

```sql
CREATE DATABASE sentinel_noc_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sentinel_test'@'localhost' IDENTIFIED BY '<local-test-password>';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
    ON sentinel_noc_test.* TO 'sentinel_test'@'localhost';
```

In the PowerShell window used for Maven, configure only that test database:

```powershell
$env:SENTINEL_MYSQL_TEST_URL = "jdbc:mysql://localhost:3306/sentinel_noc_test?connectTimeout=5000&socketTimeout=10000&serverTimezone=UTC"
$env:SENTINEL_MYSQL_TEST_USER = "sentinel_test"
$env:SENTINEL_MYSQL_TEST_PASSWORD = "<local-test-password>"
mvn clean test
```

Independently verify the URL database name is `sentinel_noc_test` and credentials are scoped only to that
database. The test condition also requires a database name ending in `_test`. Integration tests retain random
records; use only a disposable test database and never point them at production.

Run:

```powershell
mvn clean test
mvn clean package
git diff --check
```

## Verification and limitations

### Verified in this implementation

- Source audit confirmed Phase 5 repository contracts, transaction boundaries, startup recovery, 2,000-alert
  per-import retention, and background UI query paths.
- `mvn clean test-compile` — **BUILD SUCCESS** on Java 17; compiled test class bytecode is Java 17 (major version 61).
- `mvn -Dtest=NetworkPacketTest test` — **1 passed, 0 failed, 0 skipped**, confirming JUnit Platform discovery.
- `mvn -Dtest=MySqlImportPersistenceTest test` — **6 passed, 0 failed, 0 skipped** on the configured MariaDB 10.4.32
  database. Repeated the class a second time with the same result.
- `mvn clean test` — **BUILD SUCCESS**, 72 passed, 0 failed, 0 errors, 0 skipped. The Surefire reports comprise
  10 XML files; `target/surefire-reports/TEST-com.soc.persistence.MySqlImportPersistenceTest.xml` records all six
  MariaDB tests as executed.
- Read-only row-count checks before and after the repeated integration runs/full suite showed unchanged totals:
  20 import sessions, 10 alerts, 3 rule configurations, and 2 migration markers. These pre-existing test database
  rows were not deleted.
- `git diff --check` succeeded.
- The SQLite migration utility's read-only source mode was tested by attempting DDL against a temporary SQLite
  database; the write was rejected and the source file size/schema remained unchanged. The MariaDB migration
  integration case used a generated temporary SQLite fixture only; no user SQLite database was migrated.
- Maven reported the existing six JavaFX Controls dependency-model warnings.
- The source supports connection-per-operation, parameterized CRUD, transactional import completion, and bounded
  dashboard query APIs.

### Environment-dependent / not yet verified

- The XAMPP GUI/startup path and the identity of the Windows service/process were not independently inspected; the
  server itself was identified by JDBC as MariaDB 10.4.32 on the verified test URL.
- Production credentials, production schema rollout, backup restoration, and migration of a real SQLite database
  have not been executed.
- GUI behavior, JavaFX Application Thread behavior under a live MySQL outage, and the complete visual import
  lifecycle were not manually checked.
- The prior Phase 4 `ProgressBar.progress : A bound value cannot be set` warning was not reproduced in a visible
  import; this phase does not claim it is resolved.
- Automated database tests do not replace operational validation, production backup/recovery rehearsal, load
  testing, or manual UI verification.
- SQLite migrations require the source schema version 1 and a stable, closed source file. Future SQLite schemas
  need an explicit migration update.
