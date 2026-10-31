# Repository Audit

## Current Architecture

- Maven desktop application using package `com.soc`.
- `MainApp` creates a JavaFX stage and connects a controller to a programmatically built dashboard view.
- The controller owns an observable alert list and calls a firewall service.
- `NidsEngine` opens a Pcap4J live capture handle and applies a basic per-source IPv4/TCP heuristic.
- JavaFX controls are built in Java; there are no FXML, CSS, or resource files.

## Existing Features

- Java 17 and JavaFX 21.0.1 are configured.
- Pcap4J core and static packet factory dependencies are configured.
- Basic alert and risk-level models exist.
- The dashboard can display alerts and offers firewall block/unblock actions.
- `mvn test` succeeds on the current environment, but no tests are present.

## Missing Features

- Offline PCAP import, bounded processing pipeline, configurable detection rules, alert persistence and lifecycle.
- UI navigation, FXML/CSS, functional monitoring controls, real dashboard aggregates, and export implementation.
- Database/configuration management, structured logging, and automated tests.
- Implementations for `GeoIpService`, `AlertExportService`, `NetworkDeviceModel`, and `AppConfig`.

## Technical Risks

- `NidsEngine` catches and discards all exceptions, uses mutable state without safe lifecycle coordination, and only evaluates IPv4/TCP packets.
- Capture is not connected to the application UI; the controller does not start or configure the engine.
- `FirewallService` interpolates unvalidated input into operating-system commands and modifies the host firewall. This is outside the requested default watchlist behavior and must not be invoked as part of normal monitoring.
- There is no persistence, test coverage, or explicit handling for capture permissions, shutdown, or overload.
- Maven emits dependency-model warnings while resolving JavaFX 21.0.1.

## Proposed Implementation Plan

1. Establish an FXML/CSS JavaFX shell, application lifecycle handling, and structured logging.
2. Implement offline PCAP processing with bounded work, isolated detection rules, alert evidence, and unit tests.
3. Connect processed data to alerts, dashboard aggregates, and CSV export; add persistence only with an explicit schema/configuration design.
4. Expand the remaining modules as functional vertical slices. Keep IP management non-enforcing unless a separately confirmed, audited enforcement module is designed.
