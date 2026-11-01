# Offline PCAP Pipeline

## Processing flow

`PcapFileReader` streams classic PCAP records from disk. `PcapPacketParser` uses Pcap4J's static packet factory to normalize Ethernet/IP/TCP/UDP/ICMP/DNS metadata into `NetworkPacket`. `PcapImportService` sends each parsed packet directly through the bounded `TrafficAggregator` and `DetectionEngine` on the JavaFX `Task` worker. On success, `SqliteImportPersistence` inserts the bounded alert batch and marks its import session `COMPLETED` in one SQLite transaction. The controller refreshes bounded observable lists from persistence on the worker executor, then applies results on the JavaFX Application Thread.

There is no intermediate unbounded queue: file reading, parsing, aggregation, and rule evaluation are sequential on one worker thread. Progress is reported in batches, traffic display is limited to 500 records, and dashboard queries load at most 500 alerts and 100 import sessions at a time. Cancellation prevents partial alert persistence; a session row remains with `CANCELLED`. Import errors are recorded as `FAILED`. A `RUNNING` session left by an abrupt shutdown is changed to `INTERRUPTED` at the next startup.

## Input support and validation

The reader supports classic PCAP v2.4 in little- or big-endian byte order and microsecond or nanosecond timestamp precision. It currently accepts Ethernet link type 1 only. PCAPNG, unsupported link types, truncated record headers/data, invalid timestamps, invalid file signatures, and configured size/record-limit violations fail the import with an error.

Pcap4J 1.8.2 has native-backed `PcapHandle.openOffline` APIs; the importer intentionally does not use them. The file reader is pure Java and packet decoding uses the existing static packet factory dependency, so offline imports do not require a native capture driver.

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

The import retains at most 2,000 generated alerts for persistence and reports further findings omitted by this per-import limit. The persistent repository does not prune historical records. The dashboard queries the most recent 500 alerts or up to 500 alerts for a selected import, and displays the most recent 100 import sessions. The in-memory repository remains only as a test implementation.

## SQLite persistence

Xerial SQLite JDBC is used without an ORM. The default database is `%LOCALAPPDATA%\SentinelNOC\sentinel_noc.db` on Windows, or `~/.local/share/SentinelNOC/sentinel_noc.db` elsewhere. Override the location with the JVM property `sentinel.db.path`. `SqliteDatabase` opens a new connection per operation, enables foreign keys and a bounded busy timeout, and stores the schema version in `PRAGMA user_version`. Schema version 1 creates:

- `import_sessions`, the parent record for every PCAP import.
- `intrusion_alerts`, with a foreign key to its import session, event timestamp seconds/nanoseconds, rule identity, severity, description, evidence, and status.
- `detection_rule_configs`, with one row per supported rule.

Creating or completing an import uses transactions. Completion updates the session and inserts its alerts atomically; on a failure the transaction rolls back and the service records `FAILED` if storage remains available. Session `alerts_created` records detection findings generated, while only up to 2,000 alert rows are stored for that import. The only configured thresholds/time window are saved through **Save Rules** or immediately before an import. Missing rule rows are initialized with the existing defaults; partial or inconsistent stored configurations are reported rather than silently replaced. If the database cannot initialize, the dashboard remains available in degraded mode but disables imports.

Before a file-copy backup or restore, close the application. Copy `sentinel_noc.db` to a safe location; restore by closing the app and replacing the database file. Keep backups separate from the application data directory. No automatic cleanup or database reset is performed.

Synthetic PCAP frames used by unit tests are generated in test code and are not production traffic or shipped sample captures.
