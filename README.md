# Sentinel NOC

Sentinel NOC is a JavaFX desktop IDS prototype with an offline PCAP import and heuristic detection pipeline.

## Requirements

- JDK 17
- Maven 3.8+
- Windows, Linux, or macOS with a JavaFX-supported desktop

Pcap4J 1.8.2 is used to decode packet metadata. The offline reader is implemented in Java and does not require Npcap/libpcap. MySQL Connector/J 9.2.0 stores import history, alerts, and detection-rule settings through the MySQL wire
protocol. MariaDB 10.4.32/XAMPP is the selected target and has been verified by the repository's server-backed
integration tests. This verification does not include production rollout or manual GUI validation.

## Run

Install MariaDB 10.4.32 (XAMPP), then initialize the database and application account using
[database/mysql/init.sql](database/mysql/init.sql). Replace its password placeholder locally before running it
with a MariaDB administrator account. Do not configure Sentinel NOC with the MariaDB `root` account.

Set the connection configuration in the environment before launching. The password is required and is never
stored in the repository:

```powershell
$env:SENTINEL_DB_URL = "jdbc:mysql://localhost:3306/sentinel_noc?connectTimeout=5000&socketTimeout=10000&tcpKeepAlive=true&serverTimezone=UTC"
$env:SENTINEL_DB_USER = "sentinel_app"
$env:SENTINEL_DB_PASSWORD = "<your-local-application-password>"
mvn javafx:run
```

`SENTINEL_DB_URL` and `SENTINEL_DB_USER` have local defaults; `SENTINEL_DB_PASSWORD` must be set. If MariaDB,
credentials, schema privileges, or schema migration are unavailable, the dashboard reports the storage failure
and disables import. There is no SQLite or in-memory fallback in the application.

```powershell
mvn clean test
```

MariaDB integration tests require a dedicated database whose name ends with `_test` and verify the server reports
MariaDB 10.4.32 before schema initialization. Set
`SENTINEL_MYSQL_TEST_URL`, `SENTINEL_MYSQL_TEST_USER`, and `SENTINEL_MYSQL_TEST_PASSWORD` to enable them.
Without a matching test URL, those tests are reported as skipped, not passed. A matching URL with missing
credentials or a server other than MariaDB 10.4.32 fails setup explicitly. The tests remove only rows and migration
markers created by their own random test identifiers and restore the rule configurations and pre-existing `RUNNING` session states
present before each test;
they do not truncate tables or remove pre-existing test database data. Use a disposable test database regardless.

## Import a capture

1. Select **Select File** and choose a readable `.pcap` file.
2. Confirm the selected file and resource limits in the import panel.
3. Keep or adjust the detection-rule thresholds and enabled checkboxes.
4. Choose **Start Import**. Parsing and detection run on a background worker; **Cancel** stops the current import.
5. Review the parsed metadata under **Traffic Sample** and the evidence for findings under **Recent Alerts** (double-click an alert).

Supported input is classic PCAP v2.4, Ethernet link type 1, with IPv4/IPv6 packet decoding. IPv4/IPv6 TCP, UDP, ICMP and ICMPv6 metadata are recognized; DNS query names are shown when Pcap4J can decode the question. Non-IP Ethernet frames are counted as unsupported, malformed frames are counted separately. PCAPNG, non-Ethernet link types, live capture, and packet payload inspection are not supported by this phase.

Detection thresholds and the shared observation window (1–3,600 seconds) can be configured in the import panel. Defaults use a 10-second event-time window:

| Rule | Default threshold | Meaning |
|---|---:|---|
| Port scan heuristic | 15 | Distinct observed TCP destination ports per source; does not establish connection success |
| TCP SYN rate heuristic | 100 | Bare SYN packets per source; not proof of a SYN flood |
| ICMP traffic threshold | 100 | ICMP/ICMPv6 packets per source; ICMP is not inherently malicious |

Alerts are suppressed per rule and source for 10 seconds of **PCAP event time**, not wall-clock processing time. Out-of-order packets within the retained window are aggregated using their capture timestamps. Packets arriving later than the current source watermark minus the retention window are excluded from rule statistics and counted as late drops. Rule settings are restored at startup; use **Save Rules** to persist edited settings, and each import also saves its active settings before processing.

Rule metrics trigger when they are greater than or equal to their configured threshold. Evidence includes the rule ID/name, source, observed metric, threshold, and observation-window duration; the alert timestamp is the triggering packet's PCAP timestamp. Findings are heuristics, not confirmation that a host or packet is malicious.

## Resource and storage limits

- Maximum file size: 512 MiB.
- Maximum packet records per import: 1,000,000.
- Maximum captured bytes per packet: 16 MiB.
- At most 500 recent packets are displayed per import.
- Traffic aggregation tracks at most 10,000 sources, 4,096 timestamp buckets per source, and 100,000 buckets total.
- At most 2,000 generated alerts are retained for one import. The import summary reports additional findings omitted by that limit.
- Aggregation capacity evictions and late packet exclusions are counted and shown in the import summary; capacity eviction can reduce detection visibility.
- The dashboard loads at most 500 recent alerts and 100 recent import sessions at a time; the database does not automatically delete older records.

## MySQL storage and SQLite migration

MySQL stores the `import_sessions`, `intrusion_alerts`, and `detection_rule_configs` tables. Schema versions are
tracked in `schema_migrations`; the application creates and migrates these tables without resetting existing data.
Database creation and runtime schema migration require the application account to have privileges only on
`sentinel_noc`.

Phase 5 data remains in its SQLite file and is not imported automatically. Back up the SQLite database and stop the
application before migrating. With MySQL configured, run the migration explicitly:

```powershell
mvn "-Dexec.mainClass=com.soc.persistence.SqliteToMySqlMigration" `
    "-Dexec.args=C:\path\to\sentinel_noc.db" exec:java
```

The migration opens SQLite read-only, preserves session/alert IDs, evidence, event timestamps, statuses, and rule
settings, checks source/target row counts, and records completion in MySQL to make repeat runs safe. See
[PHASE_6_MYSQL_MIGRATION.md](PHASE_6_MYSQL_MIGRATION.md) for backup, migration, and recovery procedures.

Import parsing and detection still run in the background. Successful session and alert writes commit together;
failed or cancelled imports retain their terminal history status without partial alerts.

Input packet payloads are parsed only as protocol metadata. The application does not execute payloads, change firewall configuration, or transmit capture data to external services.

See [docs/PCAP_PIPELINE.md](docs/PCAP_PIPELINE.md) for pipeline behavior and limitations, and
[PHASE_5_PERSISTENCE.md](PHASE_5_PERSISTENCE.md) for the historical SQLite implementation.
