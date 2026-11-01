package com.soc.detection;

import com.soc.model.RiskLevel;

import java.util.Optional;

public record RuleFinding(
        String ruleId,
        String ruleName,
        String description,
        RiskLevel severity,
        String evidence,
        Optional<String> sourceAddress,
        Optional<String> destinationAddress) {
}
