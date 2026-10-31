package com.soc.detection;

import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;

public final class PortScanRule extends AbstractThresholdRule {
    public static final String ID = "PORT_SCAN";

    public PortScanRule(DetectionRuleConfig config) {
        super(config);
        if (!ID.equals(config.id())) {
            throw new IllegalArgumentException("Port scan rule ID must be " + ID);
        }
    }

    @Override
    protected boolean accepts(NetworkPacket packet) {
        return packet.protocol() == Protocol.TCP && packet.destinationPort().isPresent();
    }

    @Override
    protected long metric(TrafficWindowSnapshot snapshot) {
        return snapshot.uniqueTcpDestinationPorts();
    }

    @Override
    protected String metricName() {
        return "unique TCP destination ports";
    }
}
