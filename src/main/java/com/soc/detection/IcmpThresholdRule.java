package com.soc.detection;

import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;

public final class IcmpThresholdRule extends AbstractThresholdRule {
    public static final String ID = "ICMP_RATE";

    public IcmpThresholdRule(DetectionRuleConfig config) {
        super(config);
        if (!ID.equals(config.id())) {
            throw new IllegalArgumentException("ICMP rule ID must be " + ID);
        }
    }

    @Override
    protected boolean accepts(NetworkPacket packet) {
        return packet.protocol() == Protocol.ICMP || packet.protocol() == Protocol.ICMPV6;
    }

    @Override
    protected long metric(TrafficWindowSnapshot snapshot) {
        return snapshot.icmpPacketCount();
    }

    @Override
    protected String metricName() {
        return "ICMP packets";
    }
}
