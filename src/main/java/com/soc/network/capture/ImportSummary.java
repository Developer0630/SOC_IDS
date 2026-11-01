package com.soc.network.capture;

import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;

import java.util.List;

public record ImportSummary(
        long packetsRead,
        long packetsParsed,
        long unsupportedPackets,
        long malformedPackets,
        long alertsGenerated,
        int trackedSources,
        long latePacketsDropped,
        long aggregationCapacityDroppedPackets,
        long aggregationEvictedSources,
        long aggregationEvictedBuckets,
        int alertsSubmittedToRepository,
        long alertsOmittedByImportLimit,
        List<IntrusionAlert> alerts,
        List<NetworkPacket> trafficSample) {

    public ImportSummary {
        alerts = List.copyOf(alerts);
        trafficSample = List.copyOf(trafficSample);
    }
}
