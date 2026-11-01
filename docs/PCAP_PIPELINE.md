# Offline PCAP Pipeline

## Processing flow

`PcapFileReader` streams classic PCAP records from disk. `PcapPacketParser` uses Pcap4J's static packet factory to normalize Ethernet/IP/TCP/UDP/ICMP/DNS metadata into `NetworkPacket`. `PcapImportService` sends each parsed packet directly through the bounded `TrafficAggregator` and `DetectionEngine` on the JavaFX `Task` worker. On success, `MySqlImportPersistence` inserts the bounded alert batch and marks its import session `COMPLETED` in one MySQL transaction. The controller refreshes bounded observable lists from persistence on the worker executor, then applies results on the JavaFX Application Thread.

Live monitoring uses `Pcap4jLivePacketSource` to enumerate and open only the user-selected interface in
non-promiscuous mode. `LiveCaptureService` owns one capture worker, passes each captured record through the same
`PcapPacketParser` and `DetectionEngine`, and retains bounded metadata samples and observed IP/MAC endpoint
statistics. The UI receives snapshots on the JavaFX Application Thread. Payload bytes are transient to parsing and
are not included in the live metadata or database.

A live session uses the existing import-session repository contract (`file_name` is `LIVE: <interface>`). Alerts
are committed atomically with the completed session when capture stops, subject to the existing 2,000-alert
session limit. If the application exits unexpectedly, startup marks the session `INTERRUPTED`; alerts that were
still held in memory are not recoverable. This is intentionally not an incremental live-alert persistence design.

There is no intermediate unbounded queue: file reading, parsing, aggregation, and rule evaluation are sequential on one worker thread. Progress is reported in batches, traffic display is limited to 500 records, and dashboard queries load at most 500 alerts and 100 import sessions at a time. Cancellation prevents partial alert persistence; a session row remains with `CANCELLED`. Import errors are recorded as `FAILED`. A `RUNNING` session left by an abrupt shutdown is changed to `INTERRUPTED` at the next startup.

## Input support and validation

The reader supports classic PCAP v2.4 in little- or big-endian byte order and microsecond or nanosecond timestamp precision. It currently accepts Ethernet link type 1 only. PCAPNG, unsupported link types, truncated record headers/data, invalid timestamps, invalid file signatures, and configured size/record-limit violations fail the import with an error.

Pcap4J 1.8.2 has native-backed `PcapHandle.openOffline` APIs; the importer intentionally does not use them. The file reader is pure Java and packet decoding uses the existing static packet factory dependency, so offline imports do not require a native capture driver.

Live capture does require a working Npcap/libpcap installation and sufficient OS permission. It is passive and
non-promiscuous: the selected adapter may not receive all traffic on a switched network, and host configuration,
Wi-Fi isolation, VPNs, or offload behavior may further constrain visibility. Runtime interface capture has not
been verified in the target environment. A missing driver, inaccessible interface, or permission failure is
reported rather than falling back to another source.

Packets shorter than an Ethernet header, IP packets whose declared length exceeds their captured bytes, or frames that the parser cannot decode are counted as malformed. Non-IP Ethernet packets are counted as unsupported. These packets are not treated as alerts. Packet payloads are not stored or executed. DNS question metadata is included only for successfully decoded DNS requests.

## Event-time aggregation and rules

The aggregator uses each packet's PCAP timestamp. Per-source windows include records at both window boundaries. Packets may arrive out of timestamp order: packets within the retained interval are inserted by timestamp; records older than the source's latest timestamp minus the maximum configured window are ignored for aggregation. This is a bounded, single-pass strategy and does not reorder/replay prior detections when late records arrive.

Implemented rules:

- `PORT_SCAN`: unique observed TCP destination ports per source, not confirmed successful connections.
- `SYN_RATE`: observed bare TCP SYN packets (`SYN=1`, `ACK=0`) per source; heuristic only.
- `ICMP_RATE`: observed ICMP and ICMPv6 packets per source; high ICMP volume is not inherently malicious.

All rules have validated positive thresholds, enabled state, severity, and a shared configurable observation window from 1 to 3,600 seconds (10 seconds by default). A rule triggers when its observed metric is greater than or equal to the configured threshold. Findings include rule ID and name, source, observed metric, configured threshold, and window; the alert timestamp is the event time of the packet that caused the threshold to be met. Suppression is keyed by rule and source and uses event time with a 10-second cooldown.

Aggregation is bounded to 10,000 source IPs, 4,096 timestamp buckets per source, and 100,000 buckets total. When those limits require eviction, evicted sources/buckets and the number of packets dropped from aggregation are included in `ImportSummary`; evicted data is not evaluated again. Late packet drops are counted separately. These exclusions can reduce detection visibility and should be considered when interpreting a clean result.

## Persistence and limitations

Each import or live session retains at most 2,000 generated alerts for persistence and reports further findings
omitted by the per-session limit. The persistent repository does not prune historical records. The dashboard
queries the most recent 500 alerts or up to 500 alerts for a selected import, and displays the most recent 100
sessions. The in-memory repository remains only as a test implementation.

Live endpoint information is limited to observed IP/MAC values, packet counts, and first/last-seen timestamps.
These values do not verify device identity; hostname, owner, device baseline, policy exceptions, separate detection
confidence, and investigation statuses are not implemented. The schema's alert status remains `NEW`, and no
automated blocking or enforcement is performed. Failed connection detection is not inferred because the parser
does not provide reliable connection outcomes.

## MySQL persistence

MySQL Connector/J is used without an ORM or shared JDBC connection pool. Each persistence operation opens and closes
its own connection; JDBC calls are made from the existing background worker. Configure `SENTINEL_DB_URL`,
`SENTINEL_DB_USER`, and `SENTINEL_DB_PASSWORD`. The default JDBC URL targets `localhost:3306/sentinel_noc` and
sets connection/socket timeouts. The application rejects the MySQL `root` user and does not fall back to SQLite or
in-memory persistence. `MySqlDatabase` tracks schema versions in `schema_migrations` and serializes startup migration
with a MySQL advisory lock. Version 1 creates:

- `import_sessions`, the parent record for every PCAP import.
- `intrusion_alerts`, with a foreign key to its import session, event timestamp seconds/nanoseconds, rule identity, severity, description, evidence, and status.
- `detection_rule_configs`, with one row per supported rule.

`schema_migrations` stores schema version and `sentinel_data_migrations` records explicit SQLite data imports.
Indexes cover alert event time, import/time, rule ID, and severity. Event time is stored as integer seconds plus
nanoseconds to preserve the PCAP timestamp exactly; evidence is stored as text without Java object serialization.

Import creation/completion and alert writes use transactions. Completion updates the session and inserts alerts
atomically; a failed write rolls back and the service reports persistence failure rather than a successful import.
Session `alerts_created` is the number of detection findings, while up to 2,000 alert rows are retained per import;
additional findings are reported as omitted. Dashboard reads remain bounded to 500 alerts (including per-import
queries) and 100 sessions. No automatic history pruning is performed. Missing rule rows use existing defaults;
partial or inconsistent configuration is reported instead of silently replaced.

MySQL DDL is not treated as transactional: startup uses idempotent `CREATE TABLE IF NOT EXISTS` statements and
records a schema version only after all v1 tables are created. A startup lock prevents concurrent schema migration.
Unknown future versions are rejected without resetting existing tables. The app account needs schema DDL privileges
on `sentinel_noc`; setup is documented in [database/mysql/init.sql](../database/mysql/init.sql).

SQLite from Phase 5 is no longer an application backend. An explicit migration command opens the source in
query-only mode, validates schema and foreign keys, copies session/alert rows transactionally, verifies counts,
and writes a completion marker. It does not modify or delete the source file. Close the old application and make a
separate SQLite backup before migration. See [PHASE_6_MYSQL_MIGRATION.md](../PHASE_6_MYSQL_MIGRATION.md).

Synthetic PCAP frames used by unit tests are generated in test code and are not production traffic or shipped sample captures.
