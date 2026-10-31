package com.soc.detection;

import com.soc.model.NetworkPacket;

import java.util.Optional;

public interface DetectionRule {
    DetectionRuleConfig config();

    Optional<RuleFinding> evaluate(NetworkPacket packet, TrafficWindowSnapshot snapshot);
}
