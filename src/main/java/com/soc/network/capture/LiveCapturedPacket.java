package com.soc.network.capture;

import com.soc.network.parser.PacketParseResult;

import java.util.Objects;

public record LiveCapturedPacket(PacketParseResult parseResult, long originalLength) {
    public LiveCapturedPacket {
        Objects.requireNonNull(parseResult, "parseResult");
        if (originalLength < 0) {
            throw new IllegalArgumentException("Original packet length cannot be negative");
        }
    }
}
