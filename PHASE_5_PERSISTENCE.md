# Phase 5 — SQLite Persistence

> **Historical implementation note:** Phase 6 replaces SQLite as the application's active persistence backend
> with MySQL. SQLite remains a JDBC dependency only to read existing Phase 5 databases during the explicit,
> read-only migration tool. Phase 5 test results and decisions below describe the implementation at that point in
> project history; for current setup and behavior see [PHASE_6_MYSQL_MIGRATION.md](PHASE_6_MYSQL_MIGRATION.md).

## Architecture

The IDS pipeline remains unchanged through packet parsing, aggregation, and detection. `PcapImportService` now depends on `ImportPersistence` rather than the test-only bounded repository:

1. Insert an import session as `RUNNING`.
2. Read, parse, aggregate, and evaluate the PCAP on the existing background worker.
3. If processing fails or is cancelled, write `FAILED` or `CANCELLED` with the processed counters and no partial alerts.
4. On success, insert generated alerts and update the import session to `COMPLETED` in one SQLite transaction.
5. Refresh dashboard data using background tasks and replace observable lists on the JavaFX Application Thread.

Database connections are opened per operation, with foreign-key checks and a 5-second busy timeout enabled. JDBC statements are parameterized; result sets, statements, and connections use try-with-resources. No connection is shared across threads.

The requested `REPOSITORY_AUDIT.md` was not present at the repository root during this phase. The audit therefore used the available README, pipeline and Phase 4 reports, Maven configuration, current production sources, and all test sources.

## Database path and degraded mode

Default location:

- Windows: `%LOCALAPPDATA%\SentinelNOC\sentinel_noc.db`
- Other platforms: `~/.local/share/SentinelNOC/sentinel_noc.db`

Set the JVM property `sentinel.db.path` to choose another database file. The database is not written under resources or Maven `target`.

The application initializes storage before loading the UI. If initialization or initial settings loading fails, it logs and displays the error, starts the dashboard with default settings, and disables imports. A later database query failure is displayed and also disables further imports. This avoids claiming durable persistence when it is unavailable. SQL persistence errors propagate to the import task; they are not converted into successful imports.

## Schema and versioning

Schema version is SQLite `PRAGMA user_version`; the current value is **1**. Version 0 creates the schema in a transaction. Databases at a newer unrecognized version fail initialization without deleting or rewriting their contents.

| Table | Contents |
|---|---|
| `import_sessions` | UUID, file name, processing start/completion times, `RUNNING`/`COMPLETED`/`FAILED`/`CANCELLED`/`INTERRUPTED`, packet counters, generated-alert count, error summary |
| `intrusion_alerts` | Alert UUID, import-session foreign key, exact PCAP event timestamp seconds/nanoseconds, optional addresses, rule ID/name, severity, description, evidence, status |
| `detection_rule_configs` | Supported rule ID, validated threshold, shared observation-window seconds, enabled flag, updated time |

Indexes cover alert event time, import/time, rule ID, and severity. Alert event time is stored as integer seconds plus nanoseconds to preserve PCAP timestamps exactly and sort correctly. Evidence is stored as text exactly as generated; no Java object serialization is used.

There is deliberately no `app_settings` table because this UI currently has no persistent application preference such as a saved theme.

At startup, existing `RUNNING` sessions are marked `INTERRUPTED`; they are not presented as completed. There is no destructive reset or automatic history pruning.

## Alerts, sessions, and configuration

- The PCAP import starts one session with the selected file's base name.
- Alerts reference their session through a foreign key.
- A successful import inserts the alert batch and updates the session in the same transaction. The session's `alerts_created` is the count of findings generated; the stored batch can be smaller because of the existing 2,000-alert per-import cap. If a batch insert or session update fails, SQLite rolls both back.
- Failed or cancelled imports retain their terminal status and processed packet counters, but no partial alert batch is persisted.
- The service retains up to 2,000 findings per import; omitted findings are reported by the import result.
- The dashboard loads no more than 500 recent alerts, 500 alerts for a selected import, and 100 recent sessions per query. Persistent storage has no 5,000-row cap and does not delete older rows.
- Rule defaults remain unchanged. Missing rule configuration rows are initialized with the existing defaults. Partial rows or inconsistent observation windows are reported as errors rather than silently replaced.
- **Save Rules** persists validated settings; settings are also persisted before an import starts. The engine receives the same validated snapshot that was saved.

## Backup, restore, and database errors

Close Sentinel NOC before making a file-copy backup. Copy `sentinel_noc.db` to a separate safe location. To restore, close the application, replace the database file with the backup, and restart. Keep backups outside the application data directory.

Schema version can be inspected with `PRAGMA user_version` using a SQLite CLI or viewer. A locked database waits up to five seconds per connection and then reports a persistence error. A read-only, damaged, or unavailable database is reported in the UI/log; imports are disabled when storage cannot be trusted. Do not delete the database as an automatic repair action.

An import interrupted by ordinary cancellation is recorded `CANCELLED`; an import that encounters a processing error is recorded `FAILED`. A process crash may leave a `RUNNING` row, which startup converts to `INTERRUPTED`. No packet payloads or partially detected alerts are stored for incomplete imports.

## ProgressBar issue from Phase 4

Phase 4 had identified but did not resolve the reported JavaFX error `ProgressBar.progress : A bound value cannot be set`. In the completion handler, the progress property was bound to the task and then set manually. Phase 5 now unbinds that property before setting the final value; cancellation and failure also unbind before resetting it. The source path is corrected, but no automated JavaFX interaction test has exercised the full visible import lifecycle, so the reported runtime error is **not claimed as independently reproduced and confirmed resolved**.

## Tests and verification

The test suite uses temporary database files and does not read or write the user's configured database. It covers:

- First initialization, schema version inspection, and safe repeated initialization.
- Alert/session persistence across repository instances, exact evidence/timestamp restoration, and no duplicates after reopen.
- First-run default rules, saved rule restoration, and validation of invalid settings.
- `COMPLETED`, `FAILED`, `CANCELLED`, and recovered `INTERRUPTED` session states with counters.
- Import-session foreign keys and transaction rollback after a duplicate alert batch failure.
- Recent/session alert queries with explicit result limits.
- Full synthetic PCAP import through SQLite and reopening the file to retrieve the alert and its evidence.

Final automated verification on Maven 3.9.16 / Java 17.0.6:

| Test class | Run | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| DetectionEngineTest | 20 | 20 | 0 | 0 |
| InMemoryAlertRepositoryTest | 2 | 2 | 0 | 0 |
| NetworkPacketTest | 1 | 1 | 0 | 0 |
| PcapFileReaderTest | 12 | 12 | 0 | 0 |
| PcapImportServiceTest | 12 | 12 | 0 | 0 |
| PcapPacketParserTest | 8 | 8 | 0 | 0 |
| SqliteImportPersistenceTest | 6 | 6 | 0 | 0 |
| **Total** | **61** | **61** | **0** | **0** |

- `mvn clean test` — **BUILD SUCCESS**, 61 tests passed.
- `mvn clean package` — **BUILD SUCCESS**, 61 tests passed and the JAR was packaged.
- FXML and Logback configuration were parsed as XML; `git diff --check` passed.
- Maven reported six JavaFX Controls dependency-model warnings. The SQLite JDBC driver and persistence tests executed successfully on Java 17.

No human-driven application session was performed. Selecting/importing a PCAP in the UI, querying persisted data through the visual history tab, theme switching, and the complete ProgressBar lifecycle remain unverified manually. XML parsing does not prove that FXMLLoader creates the complete scene successfully.

The runtime-resolved default path on Windows is `%LOCALAPPDATA%\SentinelNOC\sentinel_noc.db`; the application was not launched against the user's profile database during validation. Tests instead used isolated temporary SQLite files.

## Remaining limitations

- Alert persistence is local to one user/profile and is not encrypted.
- File-copy backup requires the app to be closed; no in-app online backup/restore UI is implemented.
- Import/alert history is not paginated interactively yet; the UI presents bounded recent results and a selected-session result page.
- SQLite initialization and persistence have automated tests, but a full human-driven JavaFX session was not performed. The database is never populated with fake production records.
