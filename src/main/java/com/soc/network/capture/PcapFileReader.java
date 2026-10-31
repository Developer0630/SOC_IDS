package com.soc.network.capture;

import java.io.EOFException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class PcapFileReader {
    private static final int GLOBAL_HEADER_LENGTH = 24;
    private static final int RECORD_HEADER_LENGTH = 16;
    private static final int ETHERNET_LINK_TYPE = 1;
    private static final int PROGRESS_INTERVAL = 2048;

    @FunctionalInterface
    public interface PacketConsumer {
        void accept(PcapPacketRecord packet) throws IOException;
    }

    @FunctionalInterface
    public interface ProgressListener {
        void update(long bytesRead, long fileSize, long packetCount);
    }

    public record ReadSummary(long packetCount, int linkType) {
    }

    public ReadSummary read(
            Path path,
            PcapReadConfig config,
            BooleanSupplier cancelled,
            PacketConsumer consumer,
            ProgressListener progress) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(consumer, "consumer");
        Objects.requireNonNull(progress, "progress");

        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException("Selected file does not exist or cannot be read");
        }
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!fileName.endsWith(".pcap")) {
            throw new IOException("Only classic PCAP (.pcap) files are supported; PCAPNG is not supported");
        }
        long fileSize = Files.size(path);
        if (fileSize > config.maxFileBytes()) {
            throw new IOException("PCAP file exceeds the configured size limit of "
                    + config.maxFileBytes() + " bytes");
        }
        if (fileSize < GLOBAL_HEADER_LENGTH) {
            throw new IOException("File is too small to contain a classic PCAP header");
        }

        try (RandomAccessFile file = new RandomAccessFile(path.toFile(), "r")) {
            byte[] globalHeader = new byte[GLOBAL_HEADER_LENGTH];
            file.readFully(globalHeader);
            Header header = parseHeader(globalHeader);
            if (header.linkType() != ETHERNET_LINK_TYPE) {
                throw new IOException("Unsupported PCAP link type " + header.linkType()
                        + "; Ethernet captures (link type 1) are supported");
            }

            long packetCount = 0;
            while (file.getFilePointer() < fileSize) {
                if (cancelled.getAsBoolean()) {
                    throw new CancellationException("PCAP import cancelled");
                }
                if (packetCount >= config.maxPackets()) {
                    throw new IOException("PCAP exceeds the configured packet limit of " + config.maxPackets());
                }
                if (fileSize - file.getFilePointer() < RECORD_HEADER_LENGTH) {
                    throw new IOException("Truncated PCAP packet header at packet " + (packetCount + 1));
                }

                byte[] recordHeader = new byte[RECORD_HEADER_LENGTH];
                file.readFully(recordHeader);
                ByteBuffer record = ByteBuffer.wrap(recordHeader).order(header.byteOrder());
                long seconds = Integer.toUnsignedLong(record.getInt());
                long fraction = Integer.toUnsignedLong(record.getInt());
                long capturedLength = Integer.toUnsignedLong(record.getInt());
                long originalLength = Integer.toUnsignedLong(record.getInt());

                long fractionsPerSecond = header.nanosecondPrecision() ? 1_000_000_000L : 1_000_000L;
                if (fraction >= fractionsPerSecond) {
                    throw new IOException("Invalid packet timestamp fraction at packet " + (packetCount + 1));
                }
                if (capturedLength > header.snapshotLength()
                        || capturedLength > config.maxCapturedPacketBytes()
                        || capturedLength > fileSize - file.getFilePointer()) {
                    throw new IOException("Invalid or truncated captured packet length at packet " + (packetCount + 1));
                }
                if (originalLength < capturedLength) {
                    throw new IOException("Original packet length is smaller than captured length at packet "
                            + (packetCount + 1));
                }

                byte[] packetData = new byte[(int) capturedLength];
                file.readFully(packetData);
                long nanos = header.nanosecondPrecision() ? fraction : fraction * 1_000L;
                Instant timestamp;
                try {
                    timestamp = Instant.ofEpochSecond(seconds, nanos);
                } catch (RuntimeException exception) {
                    throw new IOException("Invalid packet timestamp at packet " + (packetCount + 1), exception);
                }
                consumer.accept(new PcapPacketRecord(timestamp, packetData, header.linkType(), originalLength));
                packetCount++;

                if (packetCount % PROGRESS_INTERVAL == 0) {
                    progress.update(file.getFilePointer(), fileSize, packetCount);
                }
            }

            progress.update(file.getFilePointer(), fileSize, packetCount);
            return new ReadSummary(packetCount, header.linkType());
        } catch (EOFException exception) {
            throw new IOException("PCAP file ended unexpectedly", exception);
        }
    }

    private static Header parseHeader(byte[] bytes) throws IOException {
        boolean littleEndian;
        boolean nanosecondPrecision;
        if (matches(bytes, 0xD4, 0xC3, 0xB2, 0xA1)) {
            littleEndian = true;
            nanosecondPrecision = false;
        } else if (matches(bytes, 0xA1, 0xB2, 0xC3, 0xD4)) {
            littleEndian = false;
            nanosecondPrecision = false;
        } else if (matches(bytes, 0x4D, 0x3C, 0xB2, 0xA1)) {
            littleEndian = true;
            nanosecondPrecision = true;
        } else if (matches(bytes, 0xA1, 0xB2, 0x3C, 0x4D)) {
            littleEndian = false;
            nanosecondPrecision = true;
        } else if (matches(bytes, 0x0A, 0x0D, 0x0D, 0x0A)) {
            throw new IOException("PCAPNG files are not supported; convert to classic PCAP first");
        } else {
            throw new IOException("Unrecognized PCAP file signature");
        }

        ByteBuffer header = ByteBuffer.wrap(bytes).order(
                littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        int majorVersion = Short.toUnsignedInt(header.getShort(4));
        int minorVersion = Short.toUnsignedInt(header.getShort(6));
        long snapshotLength = Integer.toUnsignedLong(header.getInt(16));
        long linkType = Integer.toUnsignedLong(header.getInt(20));
        if (majorVersion != 2 || minorVersion < 4) {
            throw new IOException("Unsupported classic PCAP version " + majorVersion + "." + minorVersion);
        }
        if (snapshotLength == 0) {
            throw new IOException("Invalid PCAP snapshot length");
        }
        if (linkType > Integer.MAX_VALUE) {
            throw new IOException("Unsupported PCAP link type");
        }
        return new Header(
                littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                nanosecondPrecision,
                snapshotLength,
                (int) linkType);
    }

    private static boolean matches(byte[] bytes, int a, int b, int c, int d) {
        return (bytes[0] & 0xFF) == a && (bytes[1] & 0xFF) == b
                && (bytes[2] & 0xFF) == c && (bytes[3] & 0xFF) == d;
    }

    private record Header(ByteOrder byteOrder, boolean nanosecondPrecision, long snapshotLength, int linkType) {
    }
}
