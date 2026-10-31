# Offline PCAP Pipeline

## Processing flow

`PcapFileReader` streams classic PCAP records from disk. `PcapPacketParser` uses Pcap4J's static packet factory to normalize Ethernet/IP/TCP/UDP/ICMP/DNS metadata into `NetworkPacket`. `PcapImportService` sends each parsed packet directly through the bounded `TrafficAggregator` and `DetectionEngine` on the JavaFX `Task` worker. The service stores generated `IntrusionAlert` records in `InMemoryAlertRepository` only after a complete import. It returns a bounded recent-traffic sample and the import summary to the controller, which updates JavaFX observable lists on the JavaFX Application Thread.

There is no intermediate unbounded queue: file reading, parsing, aggregation, and rule evaluation are sequential on one worker thread. Progress is reported in batches, traffic display is limited to 500 records, alert history is limited to 5,000 records, and cancellation prevents partial alert persistence.

## Input support and validation

The reader supports classic PCAP v2.4 in little- or big-endian byte order and microsecond or nanosecond timestamp precision. It currently accepts Ethernet link type 1 only. PCAPNG, unsupported link types, truncated record headers/data, invalid timestamps, invalid file signatures, and configured size/record-limit violations fail the import with an error.

Pcap4J 1.8.2 has native-backed `PcapHandle.openOffline` APIs; the importer intentionally does not use them. The file reader is pure Java and packet decoding uses the existing static packet factory dependency, so offline imports do not require a native capture driver.

Packets shorter than an Ethernet header or frames that the parser cannot decode are counted as malformed. Non-IP Ethernet packets are counted as unsupported. These packets are not treated as alerts. Packet payloads are not stored or executed. DNS question metadata is included only for successfully decoded DNS requests.

## Event-time aggregation and rules

The aggregator uses each packet's PCAP timestamp. Per-source windows include records at both window boundaries. Packets may arrive out of timestamp order: packets within the retained interval are inserted by timestamp; records older than the source's latest timestamp minus the maximum configured window are ignored for aggregation. This is a bounded, single-pass strategy and does not reorder/replay prior detections when late records arrive.

Implemented rules:

- `PORT_SCAN`: unique observed TCP destination ports per source, not confirmed successful connections.
- `SYN_RATE`: observed bare TCP SYN packets (`SYN=1`, `ACK=0`) per source; heuristic only.
- `ICMP_RATE`: observed ICMP and ICMPv6 packets per source; high ICMP volume is not inherently malicious.

All rules have validated positive thresholds, enabled state, severity, and a shared configurable observation window from 1 to 3,600 seconds (10 seconds by default). Findings include rule ID, source, observed metric, configured threshold, and window. Suppression is keyed by rule and source and uses event time with a 10-second cooldown.

## Persistence and limitations

The alert repository is an in-memory, bounded implementation of the repository interface. Alerts and import data are lost when the application exits; durable database persistence and alert workflow states beyond `NEW` are not implemented. The dashboard displays only the most recent 500 successfully parsed packet records and up to 5,000 session alerts.

Synthetic PCAP frames used by unit tests are generated in test code and are not production traffic or shipped sample captures.
