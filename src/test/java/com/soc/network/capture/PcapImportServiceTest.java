package com.soc.network.capture;

import com.soc.TestPcapFixtures;
import com.soc.detection.InMemoryAlertRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

        ImportSummary result = service.importFile(
                capture, UUID.randomUUID(), () -> false, (bytes, size, count) -> {
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
}
