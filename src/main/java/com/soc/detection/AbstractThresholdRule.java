package com.soc.detection;

import com.soc.model.NetworkPacket;

import java.util.Optional;

abstract class AbstractThresholdRule implements DetectionRule {
    private final DetectionRuleConfig config;

    AbstractThresholdRule(DetectionRuleConfig config) {
        this.config = config;
    }

    @Override
    public final DetectionRuleConfig config() {
        return config;
    }

    @Override
    public final Optional<RuleFinding> evaluate(NetworkPacket packet, TrafficWindowSnapshot snapshot) {
        if (!config.enabled() || !accepts(packet)) {
            return Optional.empty();
        }
        long observed = metric(snapshot);
        if (observed < config.threshold()) {
            return Optional.empty();
        }
        String source = packet.sourceAddress().orElse("unavailable");
        String evidence = "Rule: " + config.id()
                + "; source IP: " + source
                + "; observed " + metricName() + ": " + observed
                + "; configured threshold: " + config.threshold()
                + "; observation window: " + config.observationWindow().toSeconds() + " seconds";
        return Optional.of(new RuleFinding(
                config.id(), config.description(), config.severity(), evidence,
                packet.sourceAddress(), packet.destinationAddress()));
    }

    protected abstract boolean accepts(NetworkPacket packet);

    protected abstract long metric(TrafficWindowSnapshot snapshot);

    protected abstract String metricName();
}
