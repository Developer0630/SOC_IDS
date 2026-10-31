package com.soc.network.capture;

public record PcapReadConfig(long maxFileBytes, long maxPackets, int maxCapturedPacketBytes) {
    public PcapReadConfig {
        if (maxFileBytes <= 24 || maxPackets <= 0 || maxCapturedPacketBytes <= 0) {
            throw new IllegalArgumentException("PCAP resource limits must be positive");
        }
    }

    public static PcapReadConfig defaults() {
        return new PcapReadConfig(512L * 1024 * 1024, 1_000_000, 16 * 1024 * 1024);
    }
}
