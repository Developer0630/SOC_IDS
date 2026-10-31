package com.soc.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertThrows;

class NetworkPacketTest {
    @Test
    void rejectsInvalidPortsAndTcpFlagsOnNonTcpPackets() {
        assertThrows(IllegalArgumentException.class, () -> new NetworkPacket(
                Instant.EPOCH, Optional.empty(), Optional.empty(),
                OptionalInt.of(65536), OptionalInt.empty(), Protocol.TCP,
                Optional.empty(), 40, Optional.empty(), Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new NetworkPacket(
                Instant.EPOCH, Optional.empty(), Optional.empty(),
                OptionalInt.empty(), OptionalInt.empty(), Protocol.UDP,
                Optional.empty(), 40,
                Optional.of(new TcpFlags(true, false, false, false, false, false)),
                Optional.empty(), Optional.empty()));
    }
}
