package com.soc.network.capture;

import com.soc.TestPcapFixtures;
import com.soc.detection.DetectionRuleSettings;
import com.soc.detection.InMemoryAlertRepository;
import com.soc.model.AlertStatus;
import com.soc.model.RiskLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PcapImportServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void processesTrafficAndPersistsEvidenceBearingAlertsForTheSession() throws IOException {
        byte[][] frames = new byte[18][];
        for (int i = 0; i < 16; i++) {
            frames[i] = TestPcapFixtures.tcpFrame(40000, 1000 + i, 0x02);
        }
        frames[16] = TestPcapFixtures.arpFrame();
        frames[17] = TestPcapFixtures.truncatedFrame();
        Path capture = TestPcapFixtures.writeCapture(temporaryDirectory.resolve("pipeline.pcap"), frames);
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);
        UUID importId = UUID.randomUUID();

        ImportSummary result = service.importFile(
                capture, importId, () -> false, (bytes, size, count) -> {
                });

        assertEquals(18, result.packetsRead());
        assertEquals(16, result.packetsParsed());
        assertEquals(1, result.unsupportedPackets());
        assertEquals(1, result.malformedPackets());
        assertEquals(1, result.alertsGenerated());
        assertEquals(1, repository.findAll().size());
        assertEquals("PORT_SCAN", repository.findAll().get(0).ruleId());
        assertEquals(16, result.trafficSample().size());
        assertEquals(1, result.trackedSources());
        assertEquals(1, result.alertsSubmittedToRepository());
        assertEquals(0, result.alertsOmittedByImportLimit());
        assertTrue(result.alerts().get(0).evidence().contains("Port scan heuristic"));
        assertTrue(result.alerts().get(0).evidence().contains("source IP: 192.0.2.10"));
        assertTrue(result.alerts().get(0).evidence()
                .contains("observed unique TCP destination ports: 15"));
        assertTrue(result.alerts().get(0).evidence().contains("configured threshold: 15"));
        assertTrue(result.alerts().get(0).evidence().contains("observation window: 10 seconds"));
        assertEquals(RiskLevel.HIGH, result.alerts().get(0).severity());
        assertEquals(AlertStatus.NEW, result.alerts().get(0).status());
        assertEquals(importId, result.alerts().get(0).importId());
        assertEquals("198.51.100.20", result.alerts().get(0).destinationAddress().orElseThrow());
        assertEquals(Instant.ofEpochSecond(1_700_000_000, 123_470_000),
                result.alerts().get(0).timestamp());
    }

    @Test
    void normalTcpUdpDnsAndSingleIcmpTrafficDoNotTriggerRules() throws IOException {
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("normal.pcap"),
                TestPcapFixtures.tcpFrame(40000, 443, 0x10),
                TestPcapFixtures.dnsQueryFrame("example.com"),
                TestPcapFixtures.icmpFrame());
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);

        ImportSummary result = service.importFile(
                capture,
                UUID.randomUUID(),
                new DetectionRuleSettings(3, 3, 2, 10, true, true, true),
                () -> false,
                (bytes, size, count) -> {
                });

        assertEquals(3, result.packetsRead());
        assertEquals(3, result.packetsParsed());
        assertEquals(0, result.alertsGenerated());
        assertTrue(repository.findAll().isEmpty());
    }

    @Test
    void detectsSynAndIcmpFixturesAtTheirConfiguredThresholds() throws IOException {
        Path synCapture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("bare-syn.pcap"),
                TestPcapFixtures.tcpFrame(40000, 443, 0x02),
                TestPcapFixtures.tcpFrame(40000, 443, 0x02));
        Path icmpCapture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("icmp.pcap"),
                TestPcapFixtures.icmpFrame(),
                TestPcapFixtures.icmpFrame());
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);
        DetectionRuleSettings settings = new DetectionRuleSettings(100, 2, 2, 10, true, true, true);

        ImportSummary syn = service.importFile(
                synCapture, UUID.randomUUID(), settings, () -> false, (bytes, size, count) -> {
                });
        ImportSummary icmp = service.importFile(
                icmpCapture, UUID.randomUUID(), settings, () -> false, (bytes, size, count) -> {
                });

        assertEquals("SYN_RATE", syn.alerts().get(0).ruleId());
        assertEquals("ICMP_RATE", icmp.alerts().get(0).ruleId());
        assertEquals(2, repository.findAll().size());
    }

    @Test
    void capsImportAlertRetentionAndReportsOmittedFindings() throws IOException {
        int sourceCount = 2001;
        TestPcapFixtures.TimedFrame[] frames = new TestPcapFixtures.TimedFrame[sourceCount * 2];
        Instant timestamp = Instant.ofEpochSecond(1_700_000_000, 123_456_000);
        for (int i = 0; i < sourceCount; i++) {
            String source = "10." + (i / 65_536) + "." + ((i / 256) % 256) + "." + (i % 256);
            frames[i * 2] = new TestPcapFixtures.TimedFrame(
                    timestamp, TestPcapFixtures.tcpFrame(source, 40000, 80, 0x10));
            frames[i * 2 + 1] = new TestPcapFixtures.TimedFrame(
                    timestamp.plusNanos(1_000), TestPcapFixtures.tcpFrame(source, 40000, 443, 0x10));
            timestamp = timestamp.plusNanos(2_000);
        }
        Path capture = TestPcapFixtures.writeTimedCapture(
                temporaryDirectory.resolve("alert-limit.pcap"), frames);
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);

        ImportSummary result = service.importFile(
                capture,
                UUID.randomUUID(),
                new DetectionRuleSettings(2, 1_000_000, 1_000_000, 10, true, true, true),
                () -> false,
                (bytes, size, count) -> {
                });

        assertEquals(2001, result.alertsGenerated());
        assertEquals(2000, result.alertsSubmittedToRepository());
        assertEquals(1, result.alertsOmittedByImportLimit());
        assertEquals(2000, repository.findAll().size());
    }

    @Test
    void trafficSampleRetainsOnlyTheMostRecentFiveHundredPackets() throws IOException {
        byte[][] frames = new byte[550][];
        java.util.Arrays.setAll(frames, index -> TestPcapFixtures.tcpFrame(40000, 443, 0x10));
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("traffic-sample-limit.pcap"), frames);
        PcapImportService service = new PcapImportService(
                PcapReadConfig.defaults(), new InMemoryAlertRepository());

        ImportSummary result = service.importFile(
                capture, UUID.randomUUID(), () -> false, (bytes, size, count) -> {
                });

        assertEquals(550, result.packetsParsed());
        assertEquals(500, result.trafficSample().size());
        assertEquals(50, result.packetsParsed() - result.trafficSample().size());
    }

    @Test
    void cancellationDoesNotPersistPartialAlerts() throws IOException {
        byte[][] frames = new byte[16][];
        for (int i = 0; i < frames.length; i++) {
            frames[i] = TestPcapFixtures.tcpFrame(40000, 1000 + i, 0x02);
        }
        Path capture = TestPcapFixtures.writeCapture(temporaryDirectory.resolve("cancel.pcap"), frames);
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);
        AtomicInteger cancellationChecks = new AtomicInteger();

        assertThrows(CancellationException.class, () -> service.importFile(
                capture, UUID.randomUUID(),
                () -> cancellationChecks.incrementAndGet() > 5,
                (bytes, size, count) -> {
                }));
        assertEquals(0, repository.findAll().size());
    }

    @Test
    void cancellationImmediatelyAfterLastRecordDoesNotPersistAlerts() throws IOException {
        byte[][] frames = new byte[16][];
        for (int i = 0; i < frames.length; i++) {
            frames[i] = TestPcapFixtures.tcpFrame(40000, 1000 + i, 0x02);
        }
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("cancel-last-record.pcap"), frames);
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);
        AtomicInteger checks = new AtomicInteger();

        assertThrows(CancellationException.class, () -> service.importFile(
                capture, UUID.randomUUID(),
                () -> checks.incrementAndGet() > 34,
                (bytes, size, count) -> {
                }));
        assertTrue(repository.findAll().isEmpty());
    }

    @Test
    void packetLimitFailureDoesNotPersistAlertsFromEarlierRecords() throws IOException {
        byte[][] frames = new byte[16][];
        for (int i = 0; i < frames.length; i++) {
            frames[i] = TestPcapFixtures.tcpFrame(40000, 1000 + i, 0x02);
        }
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("packet-limit.pcap"), frames);
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(
                new PcapReadConfig(Files.size(capture), 15, 1024), repository);

        assertThrows(IOException.class, () -> service.importFile(
                capture, UUID.randomUUID(), () -> false, (bytes, size, count) -> {
                }));
        assertTrue(repository.findAll().isEmpty());
    }

    @Test
    void latePacketExclusionIsReportedInImportSummary() throws IOException {
        Path capture = TestPcapFixtures.writeTimedCapture(
                temporaryDirectory.resolve("late.pcap"),
                new TestPcapFixtures.TimedFrame(Instant.ofEpochSecond(1_700_000_000),
                        TestPcapFixtures.tcpFrame(40000, 80, 0x10)),
                new TestPcapFixtures.TimedFrame(Instant.ofEpochSecond(1_700_000_011),
                        TestPcapFixtures.tcpFrame(40000, 81, 0x10)),
                new TestPcapFixtures.TimedFrame(Instant.ofEpochSecond(1_700_000_000, 1_000),
                        TestPcapFixtures.tcpFrame(40000, 82, 0x10)));
        PcapImportService service = new PcapImportService(
                PcapReadConfig.defaults(), new InMemoryAlertRepository());

        ImportSummary result = service.importFile(
                capture, UUID.randomUUID(), () -> false, (bytes, size, count) -> {
                });

        assertEquals(3, result.packetsRead());
        assertEquals(3, result.packetsParsed());
        assertEquals(1, result.latePacketsDropped());
    }

    @Test
    void repeatedImportsRemainIndependentAndUseDifferentImportReferences() throws IOException {
        Path firstFile = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("first.pcap"),
                TestPcapFixtures.tcpFrame(40000, 80, 0x02),
                TestPcapFixtures.tcpFrame(40000, 81, 0x02));
        Path secondFile = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("second.pcap"),
                TestPcapFixtures.tcpFrame(40000, 80, 0x02),
                TestPcapFixtures.tcpFrame(40000, 81, 0x02));
        InMemoryAlertRepository repository = new InMemoryAlertRepository();
        PcapImportService service = new PcapImportService(PcapReadConfig.defaults(), repository);
        DetectionRuleSettings settings =
                new DetectionRuleSettings(2, 100, 100, 10, true, true, true);

        ImportSummary first = service.importFile(
                firstFile, UUID.randomUUID(), settings, () -> false, (bytes, size, count) -> {
                });
        ImportSummary second = service.importFile(
                secondFile, UUID.randomUUID(), settings, () -> false, (bytes, size, count) -> {
                });

        assertEquals(1, first.alertsGenerated());
        assertEquals(1, second.alertsGenerated());
        assertEquals(2, repository.findAll().size());
        assertTrue(!repository.findAll().get(0).importId().equals(repository.findAll().get(1).importId()));
    }
}
