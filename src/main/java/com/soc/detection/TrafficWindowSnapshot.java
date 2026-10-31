package com.soc.detection;

public record TrafficWindowSnapshot(
        long packetCount,
        long byteCount,
        int uniqueTcpDestinationPorts,
        long bareSynCount,
        long icmpPacketCount) {
}
