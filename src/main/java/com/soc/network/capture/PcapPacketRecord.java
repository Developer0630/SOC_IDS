package com.soc.network.capture;

import java.time.Instant;
import java.util.Objects;

public record PcapPacketRecord(Instant timestamp, byte[] data, int linkType, long originalLength) {
    public PcapPacketRecord {
        Objects.requireNonNull(timestamp, "timestamp");
        data = data.clone();
        if (originalLength < 0) {
            throw new IllegalArgumentException("Original packet length cannot be negative");
        }
    }

    @Override
    public byte[] data() {
        return data.clone();
    }
}
