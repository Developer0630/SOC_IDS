package com.soc.detection;

import com.soc.model.NetworkPacket;

public final class SynRateRule extends AbstractThresholdRule {
    public static final String ID = "SYN_RATE";

    public SynRateRule(DetectionRuleConfig config) {
        super(config);
        if (!ID.equals(config.id())) {
            throw new IllegalArgumentException("SYN heuristic rule ID must be " + ID);
        }
    }

    @Override
    protected boolean accepts(NetworkPacket packet) {
        return packet.tcpFlags().filter(flags -> flags.syn() && !flags.ack()).isPresent();
    }

    @Override
    protected long metric(TrafficWindowSnapshot snapshot) {
        return snapshot.bareSynCount();
    }

    @Override
    protected String metricName() {
        return "bare TCP SYN packets";
    }
}
