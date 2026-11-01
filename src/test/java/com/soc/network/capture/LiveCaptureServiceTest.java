package com.soc.network.capture;

import com.soc.detection.DetectionRuleSettings;
import com.soc.detection.InMemoryAlertRepository;
import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;
import com.soc.model.TcpFlags;
import com.soc.persistence.ImportSession;
import com.soc.persistence.ImportSessionStatus;
import com.soc.network.parser.PacketParseResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LiveCaptureServiceTest {
    @Test
    void startsOneWorkerProcessesMetadataAndPersistsTheSessionWhenStopped() throws Exception {
        InMemoryAlertRepository persistence = new InMemoryAlertRepository();
        FakePacketSource source = new FakePacketSource(List.of(
                capturedPacket(80, 60),
                capturedPacket(443, 70),
                capturedPacket(8080, 80)));
        CountDownLatch stopped = new CountDownLatch(1);
        AtomicReference<LiveCaptureSnapshot> latest = new AtomicReference<>();
        try (LiveCaptureService service = new LiveCaptureService(
                persistence,
                source,
                snapshot -> {
                    latest.set(snapshot);
                    if (snapshot.state() == LiveCaptureState.STOPPED) {
                        stopped.countDown();
                    }
                })) {
            assertEquals(1, service.listInterfaces().size());
            assertTrue(service.start(
                    "test0",
                    new DetectionRuleSettings(2, 100, 100, 10, true, true, true)));
            assertFalse(service.start(
                    "test0",
                    new DetectionRuleSettings(2, 100, 100, 10, true, true, true)));
            assertTrue(source.packetsDelivered.await(2, TimeUnit.SECONDS));

            LiveCaptureSnapshot running = service.snapshot();
            assertEquals(LiveCaptureState.RUNNING, running.state());
            assertEquals(3, running.packetsCaptured());
            assertEquals(3, running.packetsParsed());
            assertEquals(210, running.bytesCaptured());
            assertEquals(3, running.trackedFlowTuples());
            assertEquals(2, running.observedEndpoints().size());
            assertEquals(Optional.of("00:11:22:33:44:55"),
                    running.observedEndpoints().stream()
                            .filter(endpoint -> endpoint.ipAddress().equals("192.0.2.10"))
                            .findFirst().orElseThrow().macAddress());
            assertTrue(running.observedEndpoints().stream()
                    .filter(endpoint -> endpoint.ipAddress().equals("198.51.100.20"))
                    .findFirst().orElseThrow().macAddress().isEmpty());
            assertEquals(1, running.alertsGenerated());
            assertTrue(running.recentAlerts().get(0).evidence().contains("observed unique TCP destination ports: 2"));
            assertTrue(source.captureThreadName.get().startsWith("sentinel-live-capture"));

            service.stop();
            assertTrue(stopped.await(2, TimeUnit.SECONDS));
            assertEquals(LiveCaptureState.STOPPED, latest.get().state());
        }

        assertEquals(1, persistence.findAll().size());
        assertEquals(1, persistence.findRecent(10).size());
        List<ImportSession> sessions = persistence.recentImports(10);
        assertEquals(1, sessions.size());
        assertEquals(ImportSessionStatus.COMPLETED, sessions.get(0).status());
        assertEquals(3, sessions.get(0).totalRecords());
        assertEquals(3, sessions.get(0).parsedPackets());
        assertEquals("LIVE: test0", sessions.get(0).fileName());
    }

    @Test
    void marksSessionFailedWhenSelectedInterfaceCannotBeOpened() throws Exception {
        InMemoryAlertRepository persistence = new InMemoryAlertRepository();
        FakePacketSource source = new FakePacketSource(List.of()) {
            @Override
            public LiveCaptureHandle open(
                    String interfaceName,
                    Consumer<LiveCapturedPacket> packetConsumer) throws IOException {
                throw new IOException("test interface permission denied");
            }
        };
        CountDownLatch failed = new CountDownLatch(1);
        AtomicReference<LiveCaptureSnapshot> latest = new AtomicReference<>();
        try (LiveCaptureService service = new LiveCaptureService(
                persistence,
                source,
                snapshot -> {
                    latest.set(snapshot);
                    if (snapshot.state() == LiveCaptureState.FAILED) {
                        failed.countDown();
                    }
                })) {
            assertTrue(service.start("test0", DetectionRuleSettings.defaults()));
            assertTrue(failed.await(2, TimeUnit.SECONDS));
        }

        assertEquals(LiveCaptureState.FAILED, latest.get().state());
        assertTrue(latest.get().failureMessage().orElseThrow().contains("permission denied"));
        assertEquals(ImportSessionStatus.FAILED, persistence.recentImports(10).get(0).status());
    }

    private static LiveCapturedPacket capturedPacket(int destinationPort, long length) {
        Instant timestamp = Instant.parse("2025-01-01T00:00:00Z").plusMillis(destinationPort);
        NetworkPacket packet = new NetworkPacket(
                timestamp,
                Optional.of("192.0.2.10"),
                Optional.of("198.51.100.20"),
                OptionalInt.of(40_000),
                OptionalInt.of(destinationPort),
                Protocol.TCP,
                Optional.empty(),
                length,
                Optional.of(new TcpFlags(true, false, false, false, false, false)),
                Optional.of("00:11:22:33:44:55"),
                Optional.of("00:11:22:33:44:66"));
        return new LiveCapturedPacket(PacketParseResult.parsed(packet), length);
    }

    private static class FakePacketSource implements LivePacketSource {
        private final List<LiveCapturedPacket> packets;
        private final CountDownLatch packetsDelivered = new CountDownLatch(1);
        private final CountDownLatch stopRequested = new CountDownLatch(1);
        private final AtomicReference<String> captureThreadName = new AtomicReference<>();

        private FakePacketSource(List<LiveCapturedPacket> packets) {
            this.packets = packets;
        }

        @Override
        public List<LiveCaptureInterface> listInterfaces() {
            return List.of(new LiveCaptureInterface("test0", "Test interface", List.of("192.0.2.10")));
        }

        @Override
        public LiveCaptureHandle open(
                String interfaceName,
                Consumer<LiveCapturedPacket> packetConsumer) throws IOException {
            return new LiveCaptureHandle() {
                @Override
                public void loop() throws InterruptedException {
                    captureThreadName.set(Thread.currentThread().getName());
                    packets.forEach(packetConsumer);
                    packetsDelivered.countDown();
                    stopRequested.await();
                }

                @Override
                public void stop() {
                    stopRequested.countDown();
                }

                @Override
                public void close() {
                    stopRequested.countDown();
                }
            };
        }
    }
}
