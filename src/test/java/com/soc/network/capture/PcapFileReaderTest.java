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
        org.junit.jupiter.api.Assertions.assertTrue(error.getMessage().contains("PCAPNG"));
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
}
