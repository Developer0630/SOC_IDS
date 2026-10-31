package com.soc.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

public record NetworkPacket(
        Instant timestamp,
        Optional<String> sourceAddress,
        Optional<String> destinationAddress,
        OptionalInt sourcePort,
        OptionalInt destinationPort,
        Protocol protocol,
        Optional<String> dnsQueryName,
        long packetLength,
        Optional<TcpFlags> tcpFlags,
        Optional<String> sourceMac,
        Optional<String> destinationMac) {

    public NetworkPacket {
        Objects.requireNonNull(timestamp, "timestamp");
        sourceAddress = Objects.requireNonNull(sourceAddress, "sourceAddress");
        destinationAddress = Objects.requireNonNull(destinationAddress, "destinationAddress");
        sourcePort = Objects.requireNonNull(sourcePort, "sourcePort");
        destinationPort = Objects.requireNonNull(destinationPort, "destinationPort");
        Objects.requireNonNull(protocol, "protocol");
        dnsQueryName = Objects.requireNonNull(dnsQueryName, "dnsQueryName");
        tcpFlags = Objects.requireNonNull(tcpFlags, "tcpFlags");
        sourceMac = Objects.requireNonNull(sourceMac, "sourceMac");
        destinationMac = Objects.requireNonNull(destinationMac, "destinationMac");
        if (packetLength < 0) {
            throw new IllegalArgumentException("Packet length cannot be negative");
        }
        validatePort(sourcePort);
        validatePort(destinationPort);
        if (protocol != Protocol.TCP && tcpFlags.isPresent()) {
            throw new IllegalArgumentException("TCP flags can only be present for TCP packets");
        }
    }

    private static void validatePort(OptionalInt port) {
        if (port.isPresent() && (port.getAsInt() < 0 || port.getAsInt() > 65535)) {
            throw new IllegalArgumentException("Port must be between 0 and 65535");
        }
    }
}
