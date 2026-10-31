package com.soc.network.parser;

import com.soc.model.NetworkPacket;

import java.util.Optional;

public record PacketParseResult(Status status, Optional<NetworkPacket> packet) {
    public enum Status {
        PARSED,
        UNSUPPORTED,
        MALFORMED
    }

    public PacketParseResult {
        packet = packet == null ? Optional.empty() : packet;
        if ((status == Status.PARSED) != packet.isPresent()) {
            throw new IllegalArgumentException("Only successfully parsed packets may contain metadata");
        }
    }

    public static PacketParseResult parsed(NetworkPacket packet) {
        return new PacketParseResult(Status.PARSED, Optional.of(packet));
    }

    public static PacketParseResult unsupported() {
        return new PacketParseResult(Status.UNSUPPORTED, Optional.empty());
    }

    public static PacketParseResult malformed() {
        return new PacketParseResult(Status.MALFORMED, Optional.empty());
    }
}
