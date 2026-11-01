# Phase 4 — IDS Pipeline Validation

## Scope and method

Validated the offline classic-PCAP pipeline without adding live capture, machine learning, firewall enforcement, or production/demo traffic. Tests create small synthetic Ethernet frames in `src/test/java/com/soc/TestPcapFixtures.java`; they are deterministic, contain no captured user traffic, and do not require network access.

The initial clean test run before Phase 4 changes reported **31 tests: 31 passed, 0 failed, 0 skipped**. The final clean run reports **53 tests: 53 passed, 0 failed, 0 skipped**.

## Validation results

| Area | Expected result | Actual result |
|---|---|---|
| Reader formats | Accept classic PCAP byte orders and timestamp precision; reject PCAPNG, unknown signature, unsupported link type, and malformed records | Passed: little-endian microsecond and big-endian nanosecond files are decoded; invalid/unsupported files fail explicitly |
| Reader failures | Reject missing/empty files, truncated record headers/data, invalid lengths/timestamp fractions, file-size excess, and record-count excess | Passed using small generated fixtures and configurable limits |
| Parser normalization | Normalize IPv4/TCP, IPv6/UDP, ICMP/ICMPv6 and DNS query metadata; distinguish unsupported from malformed frames | Passed; malformed IP data is not counted as a valid parsed packet |
| Port-scan rule | Count unique observed TCP destination ports per source, with the configured threshold and time window | Passed for below/equal/above threshold metrics, duplicate ports, distinct sources, and the exact window boundary |
| Bare-SYN rule | Count only TCP packets with SYN set and ACK clear | Passed for bare SYN, non-SYN, SYN-ACK, threshold and time-window behavior |
| ICMP rule | Count ICMP and ICMPv6 per source without inventing port values | Passed for both protocol families, source isolation, threshold, and unrelated TCP traffic |
| Suppression and replay | Suppress by rule/source using PCAP event time; preserve different rules/sources and deterministic replay | Passed, including same timestamps, out-of-order packets within retention, exact retention boundary, late packets, and replayed findings |
| Evidence and alert data | Preserve rule ID/name, severity, source/destination when available, event timestamp, metric, threshold, window, NEW status and import ID | Passed with end-to-end import assertions |
| Import limits | Bound traffic sample, per-import alerts, repository retention and aggregation state; disclose excluded data | Passed with generated 550-packet, 2,001-alert, 5,001-alert repository, and reduced-config aggregation fixtures |
| Cancellation/failure | Stop processing and avoid persisting partial alerts when cancellation or a record-limit error occurs | Passed, including cancellation after the final record and a packet-limit failure after earlier records triggered a finding |
| Repeated imports | Keep per-import engine state independent and retain separately referenced alerts | Passed |

### Test totals

| Test class | Run | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| DetectionEngineTest | 20 | 20 | 0 | 0 |
| InMemoryAlertRepositoryTest | 2 | 2 | 0 | 0 |
| NetworkPacketTest | 1 | 1 | 0 | 0 |
| PcapFileReaderTest | 12 | 12 | 0 | 0 |
| PcapImportServiceTest | 10 | 10 | 0 | 0 |
| PcapPacketParserTest | 8 | 8 | 0 | 0 |
| **Total** | **53** | **53** | **0** | **0** |

## Verified defects and changes

1. A truncated IPv4 packet whose declared total length exceeded its captured bytes could be returned as parsed by Pcap4J, with incomplete transport metadata. The parser now checks the declared IPv4/IPv6 packet length against captured IP bytes and classifies truncation as malformed.
2. Alert evidence omitted the friendly rule name. The rule name is now carried through the finding and alert model and included in evidence/UI presentation.
3. Aggregation capacity evictions were not represented in the import result. The aggregator now counts dropped packets and evicted sources/buckets; the summary/status reports exclusions so a clean result is not mistaken for complete visibility.
4. Cancellation could arrive after the final record but before alert persistence. The service now checks cancellation after the reader returns and before saving alerts; regression tests prove no partial alerts are committed.
5. Controller task completion handlers now avoid updating controls after controller shutdown, and cancellation/failure releases progress bindings and resets progress.

## Resource-limit verification boundaries

Production defaults are asserted as **512 MiB**, **1,000,000 records**, and **16 MiB per captured packet**. Exact configured file-size and record-count boundaries, and just-over-limit behavior, are exercised with small files/configurations. The test suite does **not** create an actual 512 MiB file, a one-million-record capture, or a 16 MiB packet.

The 500-packet traffic sample, 2,000-alert per-import cap, and 5,000-alert repository retention are exercised around their limits. Aggregation source/bucket eviction is exercised with reduced test-only capacities; production-capacity-scale aggregation was not allocated in a test. No memory profiler or prolonged stress test was run.

## JavaFX and manual verification

- **Launch check:** `debugJavaApplication` reported a Java debug session started for `com.soc.MainApp`. This verifies the application can build/launch and reach JavaFX startup; the view loader is part of startup.
- **Code review only:** import parsing/detection occurs inside `Task.call()` on the single-thread executor; task progress/message updates use JavaFX `Task` APIs; success/failure/cancel handlers update controls through JavaFX task handlers; shutdown cancels the worker and guards completion handlers.
- **Not manually verified:** selecting/importing a PCAP through the visible file chooser, visually inspecting dashboard values and empty/error states, cancelling from the UI, double-clicking evidence, switching themes, closing the window mid-import, or inspecting the JavaFX Application Thread with runtime instrumentation. No interactive desktop automation was available.
- No assertion is made that JavaFX thread behavior has been instrumented at runtime; it was reviewed in code and the application launch was confirmed.

## Known limitations

- Input is classic PCAP v2.4 over Ethernet link type 1 only; PCAPNG and other link types are rejected.
- Heuristics indicate observed traffic patterns, not confirmed attacks or successful connections.
- Event-time processing is bounded and single-pass: late packets beyond retention are excluded rather than replaying prior detections.
- Aggregation capacity evictions can reduce detection visibility; counts are reported, but dropped events are not reprocessed.
- Alert persistence remains in memory and is lost when the application exits.
- A run of `mvn clean test` emitted six dependency-model warnings while resolving JavaFX Controls 21.0.1. Tests passed; Pcap4J also logged optional property fallback messages and used its defaults.
- One non-clean focused test run after launching through the Java debugger saw stale class-file version 67 in `target` while Maven ran under Java 17. A clean rebuild recompiled the project and the final full suite passed.

## Commands and outcomes

- `mvn clean test` — final result: **BUILD SUCCESS**, 53 tests passed.
- `mvn -Dtest=PcapImportServiceTest test` — one intermediate attempt failed before test execution because stale Java 23 class files remained in `target`; resolved by running the clean suite.
- `git diff --check` — passed.
- `mvn javafx:run` — documented application launch command; it was not used for the manual launch check.

Run the application from the repository root with:

```powershell
mvn javafx:run
```
