package com.soc.network.capture;

import com.soc.model.IntrusionAlert;
import com.soc.model.NetworkPacket;
import com.soc.model.ObservedEndpoint;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record LiveCaptureSnapshot(
        LiveCaptureState state,
        Optional<String> interfaceName,
        long packetsCaptured,
        long bytesCaptured,
        long packetsParsed,
        long unsupportedPackets,
        long malformedPackets,
        long alertsGenerated,
        long alertsOmitted,
        int trackedFlowTuples,
        double packetsPerSecond,
        double bytesPerSecond,
        List<NetworkPacket> recentTraffic,
        List<IntrusionAlert> recentAlerts,
        List<ObservedEndpoint> observedEndpoints,
        Optional<String> failureMessage) {

    public LiveCaptureSnapshot {
        Objects.requireNonNull(state, "state");
        interfaceName = Objects.requireNonNull(interfaceName, "interfaceName");
        failureMessage = Objects.requireNonNull(failureMessage, "failureMessage");
        recentTraffic = List.copyOf(recentTraffic);
        recentAlerts = List.copyOf(recentAlerts);
        observedEndpoints = List.copyOf(observedEndpoints);
    }

    public static LiveCaptureSnapshot idle() {
        return new LiveCaptureSnapshot(
                LiveCaptureState.IDLE, Optional.empty(), 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, List.of(), List.of(), List.of(), Optional.empty());
    }
}
