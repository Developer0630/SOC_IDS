# Sentinel NOC

Sentinel NOC is a JavaFX desktop IDS prototype with an offline PCAP import and heuristic detection pipeline.

## Requirements

- JDK 17
- Maven 3.8+
- Windows, Linux, or macOS with a JavaFX-supported desktop

Pcap4J 1.8.2 is used to decode packet metadata. The offline reader is implemented in Java and does not require Npcap/libpcap. No new dependencies are needed for PCAP import.

## Run

From the repository root:

```powershell
mvn javafx:run
```

Run the unit tests with:

```powershell
mvn clean test
```

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

Alerts are suppressed per rule and source for 10 seconds of **PCAP event time**, not wall-clock processing time. Out-of-order packets within the retained window are aggregated using their capture timestamps. Packets arriving later than the current source watermark minus the retention window are excluded from rule statistics and counted as late drops.

Rule metrics trigger when they are greater than or equal to their configured threshold. Evidence includes the rule ID/name, source, observed metric, threshold, and observation-window duration; the alert timestamp is the triggering packet's PCAP timestamp. Findings are heuristics, not confirmation that a host or packet is malicious.

## Resource and storage limits

- Maximum file size: 512 MiB.
- Maximum packet records per import: 1,000,000.
- Maximum captured bytes per packet: 16 MiB.
- At most 500 recent packets are displayed per import.
- Traffic aggregation tracks at most 10,000 sources, 4,096 timestamp buckets per source, and 100,000 buckets total.
- At most 2,000 generated alerts are retained for one import. The import summary reports additional findings omitted by that limit.
- Aggregation capacity evictions and late packet exclusions are counted and shown in the import summary; capacity eviction can reduce detection visibility.
- The in-memory alert repository retains at most 5,000 alerts for the current application session; it is not durable storage.

Input packet payloads are parsed only as protocol metadata. The application does not execute payloads, change firewall configuration, or transmit capture data to external services.

See [docs/PCAP_PIPELINE.md](docs/PCAP_PIPELINE.md) for implementation and limitations.
