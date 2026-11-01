package com.soc.network.capture;

import com.soc.network.parser.PcapPacketParser;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

public final class Pcap4jLivePacketSource implements LivePacketSource {
    private static final Logger LOGGER = LoggerFactory.getLogger(Pcap4jLivePacketSource.class);
    private static final int SNAPSHOT_LENGTH = 65_535;
    private static final int READ_TIMEOUT_MILLIS = 1_000;

    private final PcapPacketParser parser;

    public Pcap4jLivePacketSource() {
        this(new PcapPacketParser());
    }

    Pcap4jLivePacketSource(PcapPacketParser parser) {
        this.parser = Objects.requireNonNull(parser, "parser");
    }

    @Override
    public List<LiveCaptureInterface> listInterfaces() throws IOException {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            if (devices == null) {
                throw new IOException("Npcap/libpcap returned no network interface list.");
            }
            return devices.stream()
                    .map(device -> new LiveCaptureInterface(
                            device.getName(),
                            device.getDescription(),
                            device.getAddresses().stream()
                                    .map(PcapAddress::getAddress)
                                    .filter(Objects::nonNull)
                                    .map(address -> address.getHostAddress())
                                    .toList()))
                    .toList();
        } catch (PcapNativeException exception) {
            throw captureSetupFailure("Unable to enumerate network interfaces", exception);
        }
    }

    @Override
    public LiveCaptureHandle open(
            String interfaceName,
            Consumer<LiveCapturedPacket> packetConsumer) throws IOException {
        Objects.requireNonNull(interfaceName, "interfaceName");
        Objects.requireNonNull(packetConsumer, "packetConsumer");
        try {
            PcapNetworkInterface device = Pcaps.getDevByName(interfaceName);
            if (device == null) {
                throw new IOException("Selected network interface is no longer available: " + interfaceName);
            }
            PcapHandle handle = device.openLive(
                    SNAPSHOT_LENGTH,
                    PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,
                    READ_TIMEOUT_MILLIS);
            try {
                int linkType = parseLinkType(handle.getDlt());
                return new Pcap4jCaptureHandle(handle, linkType, parser, packetConsumer);
            } catch (RuntimeException exception) {
                handle.close();
                throw exception;
            }
        } catch (PcapNativeException exception) {
            throw captureSetupFailure("Unable to open capture on interface " + interfaceName, exception);
        }
    }

    private static int parseLinkType(DataLinkType linkType) {
        try {
            return Integer.parseInt(linkType.valueAsString());
        } catch (NumberFormatException exception) {
            LOGGER.warn("Capture interface returned an unrecognized link type '{}'", linkType);
            return -1;
        }
    }

    private static IOException captureSetupFailure(String action, PcapNativeException cause) {
        return new IOException(action + ". Verify that Npcap is installed and that this account has "
                + "permission to capture on the selected interface. " + cause.getMessage(), cause);
    }

    private static final class Pcap4jCaptureHandle implements LiveCaptureHandle {
        private final PcapHandle handle;
        private final int linkType;
        private final PcapPacketParser parser;
        private final Consumer<LiveCapturedPacket> packetConsumer;

        private Pcap4jCaptureHandle(
                PcapHandle handle,
                int linkType,
                PcapPacketParser parser,
                Consumer<LiveCapturedPacket> packetConsumer) {
            this.handle = handle;
            this.linkType = linkType;
            this.parser = parser;
            this.packetConsumer = packetConsumer;
        }

        @Override
        public void loop() throws Exception {
            org.pcap4j.core.PacketListener packetListener = packet -> {
                Timestamp timestamp = handle.getTimestamp();
                if (timestamp == null) {
                    throw new IllegalStateException("Capture provider did not supply a packet timestamp.");
                }
                Instant capturedAt = timestamp.toInstant();
                byte[] rawData = packet.getRawData();
                Integer providerLength = handle.getOriginalLength();
                if (providerLength == null) {
                    throw new IllegalStateException("Capture provider did not supply the original packet length.");
                }
                long originalLength = providerLength.longValue();
                PcapPacketRecord record = new PcapPacketRecord(
                        capturedAt, rawData, linkType, originalLength);
                packetConsumer.accept(new LiveCapturedPacket(
                        parser.parse(record), originalLength));
            };
            handle.loop(-1, packetListener);
        }

        @Override
        public void stop() {
            try {
                handle.breakLoop();
            } catch (org.pcap4j.core.NotOpenException exception) {
                LOGGER.debug("Capture handle was already closed while stopping");
            }
        }

        @Override
        public void close() {
            if (handle.isOpen()) {
                handle.close();
            }
        }
    }
}
