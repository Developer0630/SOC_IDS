package com.soc.network.capture;

import com.soc.TestPcapFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PcapFileReaderTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void readsClassicPcapAndPreservesMicrosecondTimestamp() throws IOException {
        Path file = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("capture.pcap"),
                TestPcapFixtures.tcpFrame(1234, 443, 0x02));
        List<PcapPacketRecord> packets = new ArrayList<>();

        PcapFileReader.ReadSummary summary = new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packets::add, (read, size, count) -> {
                });

        assertEquals(1, summary.packetCount());
        assertEquals(1, packets.get(0).linkType());
        assertEquals(123_456_000, packets.get(0).timestamp().getNano());
    }

    @Test
    void rejectsPcapngExplicitly() throws IOException {
        Path file = temporaryDirectory.resolve("capture.pcap");
        Files.write(file, new byte[]{
                0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        });

        IOException error = assertThrows(IOException.class, () -> new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
        assertTrue(error.getMessage().contains("PCAPNG"));
    }

    @Test
    void readsBigEndianNanosecondPcap() throws IOException {
        byte[] frame = TestPcapFixtures.tcpFrame(1234, 443, 0x02);
        ByteBuffer data = ByteBuffer.allocate(24 + 16 + frame.length).order(ByteOrder.BIG_ENDIAN);
        data.put(new byte[]{(byte) 0xA1, (byte) 0xB2, 0x3C, 0x4D});
        data.putShort((short) 2).putShort((short) 4);
        data.putInt(0).putInt(0).putInt(0xFFFFFFFF).putInt(1);
        data.putInt(1_700_000_000).putInt(123_456_789);
        data.putInt(frame.length).putInt(frame.length).put(frame);
        Path file = temporaryDirectory.resolve("nanosecond.pcap");
        Files.write(file, data.array());
        List<PcapPacketRecord> packets = new ArrayList<>();

        new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packets::add, (read, size, count) -> {
                });

        assertEquals(123_456_789, packets.get(0).timestamp().getNano());
    }

    @Test
    void acceptsValidClassicCaptureWithNoRecords() throws IOException {
        Path file = TestPcapFixtures.writeCapture(temporaryDirectory.resolve("empty.pcap"));

        PcapFileReader.ReadSummary result = new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                });

        assertEquals(0, result.packetCount());
    }

    @Test
    void rejectsTruncatedAndOverLimitFiles() throws IOException {
        Path truncated = temporaryDirectory.resolve("truncated.pcap");
        Files.write(truncated, new byte[]{1, 2, 3});
        assertThrows(IOException.class, () -> new PcapFileReader().read(
                truncated, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));

        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("large.pcap"), TestPcapFixtures.tcpFrame(1, 2, 2));
        assertThrows(IOException.class, () -> new PcapFileReader().read(
                capture, new PcapReadConfig(25, 100, 1024), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
    }

    @Test
    void distinguishesMissingEmptyAndInvalidHeaderFiles() throws IOException {
        Path missing = temporaryDirectory.resolve("missing.pcap");
        assertThrows(IOException.class, () -> new PcapFileReader().read(
                missing, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));

        Path empty = temporaryDirectory.resolve("physically-empty.pcap");
        Files.write(empty, new byte[0]);
        IOException emptyError = assertThrows(IOException.class, () -> new PcapFileReader().read(
                empty, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
        assertTrue(emptyError.getMessage().contains("too small"));

        Path invalid = temporaryDirectory.resolve("bad-header.pcap");
        Files.write(invalid, new byte[24]);
        IOException headerError = assertThrows(IOException.class, () -> new PcapFileReader().read(
                invalid, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
        assertTrue(headerError.getMessage().contains("signature"));
    }

    @Test
    void rejectsTruncatedPacketRecordData() throws IOException {
        ByteBuffer data = ByteBuffer.allocate(24 + 16 + 5).order(ByteOrder.LITTLE_ENDIAN);
        data.put(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        data.putShort((short) 2).putShort((short) 4);
        data.putInt(0).putInt(0).putInt(65535).putInt(1);
        data.putInt(1).putInt(0).putInt(54).putInt(54).put(new byte[5]);
        Path file = temporaryDirectory.resolve("truncated-record.pcap");
        Files.write(file, data.array());

        assertThrows(IOException.class, () -> new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
    }

    @Test
    void rejectsTruncatedRecordHeaderAndInvalidLengthsAndTimestampFraction() throws IOException {
        byte[] global = globalHeader(ByteOrder.LITTLE_ENDIAN, 65535, 1);
        Path shortRecordHeader = temporaryDirectory.resolve("short-record-header.pcap");
        byte[] shortHeaderData = java.util.Arrays.copyOf(global, global.length + 8);
        Files.write(shortRecordHeader, shortHeaderData);
        assertTrue(assertThrows(IOException.class, () -> new PcapFileReader().read(
                shortRecordHeader, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                })).getMessage().contains("Truncated PCAP packet header"));

        Path capturedOverLimit = temporaryDirectory.resolve("captured-over-limit.pcap");
        Files.write(capturedOverLimit, recordFile(global, 1, 0, 65, 65, new byte[65]));
        assertTrue(assertThrows(IOException.class, () -> new PcapFileReader().read(
                capturedOverLimit, new PcapReadConfig(1024, 10, 64), () -> false, packet -> {
                }, (read, size, count) -> {
                })).getMessage().contains("captured packet length"));

        Path originalShorter = temporaryDirectory.resolve("original-shorter.pcap");
        Files.write(originalShorter, recordFile(global, 1, 0, 10, 9, new byte[10]));
        assertTrue(assertThrows(IOException.class, () -> new PcapFileReader().read(
                originalShorter, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                })).getMessage().contains("Original packet length"));

        Path badFraction = temporaryDirectory.resolve("bad-fraction.pcap");
        Files.write(badFraction, recordFile(global, 1, 1_000_000, 1, 1, new byte[1]));
        assertTrue(assertThrows(IOException.class, () -> new PcapFileReader().read(
                badFraction, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                })).getMessage().contains("timestamp fraction"));
    }

    @Test
    void enforcesPacketLimitAndCancellation() throws IOException {
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("two.pcap"),
                TestPcapFixtures.tcpFrame(1, 2, 2),
                TestPcapFixtures.tcpFrame(1, 3, 2));
        assertThrows(IOException.class, () -> new PcapFileReader().read(
                capture, new PcapReadConfig(1024, 1, 1024), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
        assertThrows(CancellationException.class, () -> new PcapFileReader().read(
                capture, PcapReadConfig.defaults(), () -> true, packet -> {
                }, (read, size, count) -> {
                }));
    }

    @Test
    void acceptsExactlyTheConfiguredPacketLimitAndReportsBatchedProgress() throws IOException {
        byte[][] frames = new byte[2048][];
        java.util.Arrays.setAll(frames, index -> TestPcapFixtures.arpFrame());
        Path capture = TestPcapFixtures.writeCapture(
                temporaryDirectory.resolve("exact-limit.pcap"), frames);
        List<Long> reportedCounts = new ArrayList<>();

        PcapFileReader.ReadSummary result = new PcapFileReader().read(
                capture,
                new PcapReadConfig(Files.size(capture), 2048, 1024),
                () -> false,
                packet -> {
                },
                (bytes, size, count) -> reportedCounts.add(count));

        assertEquals(2048, result.packetCount());
        assertEquals(List.of(2048L, 2048L), reportedCounts);
    }

    @Test
    void productionDefaultsKeepDocumentedResourceLimits() {
        PcapReadConfig config = PcapReadConfig.defaults();

        assertEquals(512L * 1024 * 1024, config.maxFileBytes());
        assertEquals(1_000_000, config.maxPackets());
        assertEquals(16 * 1024 * 1024, config.maxCapturedPacketBytes());
    }

    @Test
    void rejectsUnsupportedLinkType() throws IOException {
        byte[] frame = TestPcapFixtures.tcpFrame(1, 2, 2);
        ByteBuffer data = ByteBuffer.allocate(24 + 16 + frame.length).order(ByteOrder.LITTLE_ENDIAN);
        data.put(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        data.putShort((short) 2).putShort((short) 4);
        data.putInt(0).putInt(0).putInt(65535).putInt(101);
        data.putInt(1).putInt(0).putInt(frame.length).putInt(frame.length).put(frame);
        Path file = temporaryDirectory.resolve("unsupported-link.pcap");
        Files.write(file, data.array());

        assertThrows(IOException.class, () -> new PcapFileReader().read(
                file, PcapReadConfig.defaults(), () -> false, packet -> {
                }, (read, size, count) -> {
                }));
    }

    private static byte[] globalHeader(ByteOrder byteOrder, int snapshotLength, int linkType) {
        ByteBuffer data = ByteBuffer.allocate(24).order(byteOrder);
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            data.put(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        } else {
            data.put(new byte[]{(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4});
        }
        data.putShort((short) 2).putShort((short) 4);
        data.putInt(0).putInt(0).putInt(snapshotLength).putInt(linkType);
        return data.array();
    }

    private static byte[] recordFile(
            byte[] globalHeader, int seconds, int fraction,
            int capturedLength, int originalLength, byte[] payload) {
        ByteBuffer data = ByteBuffer.allocate(globalHeader.length + 16 + payload.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        data.put(globalHeader);
        data.putInt(seconds).putInt(fraction).putInt(capturedLength).putInt(originalLength).put(payload);
        return data.array();
    }
}
