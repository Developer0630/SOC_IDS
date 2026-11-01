package com.soc.detection;

import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;
import com.soc.model.RiskLevel;
import com.soc.model.TcpFlags;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineTest {
    private static final Instant START = Instant.parse("2025-01-01T00:00:00Z");
    private static final String SOURCE = "192.0.2.10";

    @Test
    void detectsPortScanAtThresholdAndIncludesEvidence() {
        DetectionEngine engine = engine(
                new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));

        assertTrue(engine.process(tcp(START, SOURCE, 80, false)).isEmpty());
        var alerts = engine.process(tcp(START.plusSeconds(1), SOURCE, 443, false));

        assertEquals(1, alerts.size());
        assertEquals(PortScanRule.ID, alerts.get(0).ruleId());
        assertTrue(alerts.get(0).evidence().contains("observed unique TCP destination ports: 2"));
        assertTrue(alerts.get(0).evidence().contains("configured threshold: 2"));
        assertTrue(alerts.get(0).description().contains("Connection success is not determined"));
    }

    @Test
    void portScanWindowIncludesExactBoundaryAndExcludesOlderEvents() {
        DetectionEngine inclusive = engine(
                new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        inclusive.process(tcp(START, SOURCE, 80, false));
        assertEquals(1, inclusive.process(tcp(START.plusSeconds(10), SOURCE, 443, false)).size());

        DetectionEngine exactThreshold = engine(
                new PortScanRule(config(PortScanRule.ID, 3, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        exactThreshold.process(tcp(START, SOURCE, 80, false));
        exactThreshold.process(tcp(START.plusSeconds(1), SOURCE, 443, false));
        assertEquals(1, exactThreshold.process(tcp(START.plusSeconds(2), SOURCE, 8080, false)).size());
        assertTrue(exactThreshold.process(tcp(START.plusSeconds(3), SOURCE, 53, false)).isEmpty());
        assertEquals(4, exactThreshold.aggregator()
                .snapshot(SOURCE, START.plusSeconds(3), Duration.ofSeconds(10)).uniqueTcpDestinationPorts());

        DetectionEngine exclusive = engine(
                new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        exclusive.process(tcp(START, SOURCE, 80, false));
        assertTrue(exclusive.process(tcp(START.plusMillis(10_001), SOURCE, 443, false)).isEmpty());
    }

    @Test
    void portScanKeepsSourcesSeparateAndCountsDuplicatePortsOnce() {
        DetectionEngine engine = engine(
                new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));

        assertTrue(engine.process(tcp(START, SOURCE, 80, false)).isEmpty());
        assertTrue(engine.process(tcp(START.plusSeconds(1), SOURCE, 80, false)).isEmpty());
        assertTrue(engine.process(tcp(START.plusSeconds(2), "198.51.100.11", 443, false)).isEmpty());
        assertEquals(1, engine.process(tcp(START.plusSeconds(3), SOURCE, 443, false)).size());
    }

    @Test
    void synHeuristicCountsOnlyBareSynPackets() {
        DetectionEngine engine = engine(
                new SynRateRule(config(SynRateRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        engine.process(tcp(START, SOURCE, 80, false));
        assertTrue(engine.process(tcp(START.plusSeconds(1), SOURCE, 80, true)).isEmpty());
        var alerts = engine.process(tcp(START.plusSeconds(2), SOURCE, 81, false));

        assertEquals(1, alerts.size());
        assertTrue(alerts.get(0).evidence().contains("observed bare TCP SYN packets: 2"));
        assertTrue(alerts.get(0).description().contains("does not confirm"));
    }

    @Test
    void synHeuristicIgnoresNonSynAndSynAckTrafficAtThresholdBoundary() {
        DetectionEngine engine = engine(
                new SynRateRule(config(SynRateRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));

        assertTrue(engine.process(tcpFlags(START, SOURCE, 80, false, false)).isEmpty());
        assertTrue(engine.process(tcpFlags(START.plusSeconds(1), SOURCE, 81, true, true)).isEmpty());
        assertTrue(engine.process(tcp(START.plusSeconds(2), SOURCE, 82, false)).isEmpty());
        assertEquals(1, engine.process(tcp(START.plusSeconds(3), SOURCE, 83, false)).size());
    }

    @Test
    void icmpThresholdDetectsAtBoundaryAndIgnoresOtherProtocols() {
        DetectionEngine engine = engine(
                new IcmpThresholdRule(config(IcmpThresholdRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        assertTrue(engine.process(tcp(START, SOURCE, 80, false)).isEmpty());
        assertTrue(engine.process(icmp(START.plusSeconds(1), SOURCE)).isEmpty());
        var alerts = engine.process(icmp(START.plusSeconds(2), SOURCE));

        assertEquals(1, alerts.size());
        assertTrue(alerts.get(0).evidence().contains("observed ICMP packets: 2"));
    }

    @Test
    void icmpv4AndIcmpv6ShareTheMetricButSourcesRemainSeparate() {
        DetectionEngine engine = engine(
                new IcmpThresholdRule(config(IcmpThresholdRule.ID, 2, Duration.ofSeconds(10), true)),
                Duration.ofSeconds(10));
        assertTrue(engine.process(icmp(START, SOURCE)).isEmpty());
        assertTrue(engine.process(icmp(START.plusSeconds(1), "198.51.100.11")).isEmpty());
        assertEquals(1, engine.process(icmpv6(START.plusSeconds(2), SOURCE)).size());
    }

    @Test
    void disabledRulesDoNotCreateAlerts() {
        DetectionEngine engine = engine(
                new PortScanRule(config(PortScanRule.ID, 1, Duration.ofSeconds(10), false)),
                Duration.ofSeconds(10));

        assertTrue(engine.process(tcp(START, SOURCE, 80, false)).isEmpty());
    }

    @Test
    void suppressionIsPerRuleAndSourceAndExpiresOnEventTime() {
        DetectionEngine engine = engine(
                new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(30), true)),
                Duration.ofSeconds(10));
        engine.process(tcp(START, SOURCE, 80, false));
        assertEquals(1, engine.process(tcp(START.plusSeconds(1), SOURCE, 81, false)).size());
        assertTrue(engine.process(tcp(START.plusSeconds(2), SOURCE, 82, false)).isEmpty());

        assertEquals(1, engine.process(tcp(START.plusSeconds(12), SOURCE, 80, false)).size());
        assertTrue(engine.process(tcp(START.plusSeconds(12), SOURCE, 81, false)).isEmpty());

        String otherSource = "198.51.100.10";
        engine.process(tcp(START.plusSeconds(13), otherSource, 80, false));
        assertEquals(1, engine.process(tcp(START.plusSeconds(13), otherSource, 81, false)).size());
    }

    @Test
    void suppressionForOneRuleDoesNotSuppressAnotherRule() {
        DetectionEngine engine = new DetectionEngine(
                List.of(
                        new PortScanRule(config(PortScanRule.ID, 2, Duration.ofSeconds(10), true)),
                        new SynRateRule(config(SynRateRule.ID, 1, Duration.ofSeconds(10), true))),
                Duration.ofSeconds(10),
                UUID.randomUUID());

        assertEquals(List.of(SynRateRule.ID), engine.process(tcp(START, SOURCE, 80, false))
                .stream().map(alert -> alert.ruleId()).toList());
        var alerts = engine.process(tcp(START.plusSeconds(1), SOURCE, 443, false));

        assertEquals(List.of(PortScanRule.ID), alerts.stream().map(alert -> alert.ruleId()).toList());
    }

    @Test
    void rejectsInvalidRuleConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> config(PortScanRule.ID, 0, Duration.ofSeconds(10), true));
        assertThrows(IllegalArgumentException.class,
                () -> config(PortScanRule.ID, 1, Duration.ZERO, true));
        assertThrows(IllegalArgumentException.class,
                () -> config(PortScanRule.ID, 1, Duration.ofHours(2), true));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine(List.of(), Duration.ZERO, UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionRuleSettings(0, 100, 100, 10, true, true, true));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionRuleSettings(1, 1, 1, 3601, true, true, true));
    }

    @Test
    void defaultSettingsCanDisableIndividualRules() {
        DetectionRuleSettings settings = new DetectionRuleSettings(2, 1, 1, 10, false, false, false);
        DetectionEngine engine = DetectionEngine.defaults(UUID.randomUUID(), settings);

        assertTrue(engine.process(tcp(START, SOURCE, 80, false)).isEmpty());
        assertTrue(engine.process(tcp(START.plusSeconds(1), SOURCE, 443, false)).isEmpty());
        assertTrue(engine.process(icmp(START.plusSeconds(2), SOURCE)).isEmpty());
    }

    @Test
    void configuredObservationWindowIsUsedForEvidenceAndEvaluation() {
        DetectionRuleSettings settings = new DetectionRuleSettings(2, 100, 100, 5, true, false, false);
        DetectionEngine engine = DetectionEngine.defaults(UUID.randomUUID(), settings);
        engine.process(tcp(START, SOURCE, 80, false));

        var alerts = engine.process(tcp(START.plusSeconds(5), SOURCE, 443, false));

        assertEquals(1, alerts.size());
        assertTrue(alerts.get(0).evidence().contains("observation window: 5 seconds"));
        assertTrue(alerts.get(0).evidence().contains("Port scan heuristic"));
        assertEquals("Port scan heuristic", alerts.get(0).ruleName());
        assertEquals(START.plusSeconds(5), alerts.get(0).timestamp());
    }

    @Test
    void repeatedTimestampPacketsAggregateInTheSameEventTimeBucket() {
        TrafficAggregator aggregator = new TrafficAggregator(Duration.ofSeconds(10), 10, 10);
        aggregator.record(tcp(START, SOURCE, 80, false));
        aggregator.record(tcp(START, SOURCE, 443, false));

        TrafficWindowSnapshot snapshot = aggregator.snapshot(SOURCE, START, Duration.ofSeconds(10));
        assertEquals(2, snapshot.packetCount());
        assertEquals(2, snapshot.uniqueTcpDestinationPorts());
    }

    @Test
    void replayProducesIdenticalFindingsApartFromGeneratedIdentifiers() {
        UUID importId = UUID.randomUUID();
        DetectionEngine first = DetectionEngine.defaults(importId);
        DetectionEngine second = DetectionEngine.defaults(importId);
        List<NetworkPacket> replay = List.of(
                tcp(START, SOURCE, 80, false),
                tcp(START.plusSeconds(1), SOURCE, 443, false),
                tcp(START.plusSeconds(1), SOURCE, 8080, false));

        List<String> firstResults = replay.stream().flatMap(packet -> first.process(packet).stream())
                .map(DetectionEngineTest::findingFingerprint).toList();
        List<String> secondResults = replay.stream().flatMap(packet -> second.process(packet).stream())
                .map(DetectionEngineTest::findingFingerprint).toList();

        assertEquals(firstResults, secondResults);
        assertTrue(firstResults.stream().allMatch(result -> result.contains(START.plusSeconds(1).toString())));
    }

    @Test
    void aggregatorAcceptsInWindowOutOfOrderPacketsAndDropsTooLatePackets() {
        TrafficAggregator aggregator = new TrafficAggregator(Duration.ofSeconds(10), 10, 10);
        aggregator.record(tcp(START.plusSeconds(10), SOURCE, 80, false));
        aggregator.record(tcp(START.plusSeconds(5), SOURCE, 443, false));
        aggregator.record(tcp(START.minusMillis(1), SOURCE, 8080, false));

        TrafficWindowSnapshot snapshot =
                aggregator.snapshot(SOURCE, START.plusSeconds(10), Duration.ofSeconds(10));
        assertEquals(2, snapshot.packetCount());
        assertEquals(2, snapshot.uniqueTcpDestinationPorts());
        assertEquals(1, aggregator.latePacketsDropped());
    }

    @Test
    void aggregatorBoundsSourceAndBucketState() {
        TrafficAggregator aggregator = new TrafficAggregator(Duration.ofHours(1), 1, 2);
        aggregator.record(tcp(START, SOURCE, 80, false));
        aggregator.record(tcp(START.plusSeconds(1), SOURCE, 81, false));
        aggregator.record(tcp(START.plusSeconds(2), SOURCE, 82, false));
        aggregator.record(tcp(START, "198.51.100.11", 80, false));

        assertEquals(1, aggregator.trackedSourceCount());
        assertEquals(1, aggregator.snapshot("198.51.100.11", START, Duration.ofSeconds(10)).packetCount());
        assertEquals(0, aggregator.snapshot(SOURCE, START.plusSeconds(2), Duration.ofSeconds(10)).packetCount());
        assertEquals(1, aggregator.capacityEvictedSources());
        assertEquals(3, aggregator.capacityDroppedPackets());
    }

    @Test
    void aggregatorEnforcesGlobalBucketLimit() {
        TrafficAggregator aggregator = new TrafficAggregator(Duration.ofSeconds(60), 10, 10, 2);
        aggregator.record(tcp(START, SOURCE, 80, false));
        aggregator.record(tcp(START.plusSeconds(1), SOURCE, 81, false));
        aggregator.record(tcp(START, "198.51.100.11", 80, false));

        assertEquals(1, aggregator.trackedSourceCount());
        assertEquals(1, aggregator.snapshot(
                "198.51.100.11", START, Duration.ofSeconds(10)).packetCount());
        assertEquals(0, aggregator.snapshot(SOURCE, START, Duration.ofSeconds(10)).packetCount());
        assertEquals(1, aggregator.capacityEvictedSources());
        assertEquals(2, aggregator.capacityDroppedPackets());
    }

    @Test
    void aggregatorReportsBucketEvictionsAtPerSourceAndGlobalLimits() {
        TrafficAggregator perSource = new TrafficAggregator(Duration.ofSeconds(60), 10, 1, 10);
        perSource.record(tcp(START, SOURCE, 80, false));
        perSource.record(tcp(START.plusSeconds(1), SOURCE, 443, false));
        assertEquals(1, perSource.capacityEvictedBuckets());
        assertEquals(1, perSource.capacityDroppedPackets());

        TrafficAggregator global = new TrafficAggregator(Duration.ofSeconds(60), 10, 10, 1);
        global.record(tcp(START, SOURCE, 80, false));
        global.record(tcp(START.plusSeconds(1), SOURCE, 443, false));
        assertEquals(1, global.capacityEvictedBuckets());
        assertEquals(1, global.capacityDroppedPackets());
    }

    @Test
    void exactRetentionBoundaryIsIncludedAndJustOlderPacketIsLate() {
        TrafficAggregator aggregator = new TrafficAggregator(Duration.ofSeconds(10), 10, 10);
        aggregator.record(tcp(START.plusSeconds(10), SOURCE, 80, false));
        aggregator.record(tcp(START, SOURCE, 443, false));

        assertEquals(2, aggregator.snapshot(
                SOURCE, START.plusSeconds(10), Duration.ofSeconds(10)).packetCount());
        aggregator.record(tcp(START.minusNanos(1), SOURCE, 8080, false));
        assertEquals(1, aggregator.latePacketsDropped());
    }

    private static DetectionEngine engine(DetectionRule rule, Duration suppressionWindow) {
        return new DetectionEngine(List.of(rule), suppressionWindow, UUID.randomUUID());
    }

    private static DetectionRuleConfig config(String id, long threshold, Duration window, boolean enabled) {
        String description = switch (id) {
            case PortScanRule.ID ->
                    "Observed TCP traffic across ports. Connection success is not determined.";
            case SynRateRule.ID ->
                    "High observed bare TCP SYN volume; this heuristic does not confirm an attack.";
            case IcmpThresholdRule.ID ->
                    "Observed ICMP traffic is not inherently malicious.";
            default -> "Test rule description";
        };
        return new DetectionRuleConfig(id, id, description, threshold, window, RiskLevel.MEDIUM, enabled);
    }

    private static NetworkPacket tcp(Instant time, String source, int destinationPort, boolean ack) {
        return tcpFlags(time, source, destinationPort, true, ack);
    }

    private static NetworkPacket tcpFlags(
            Instant time, String source, int destinationPort, boolean syn, boolean ack) {
        return new NetworkPacket(
                time, Optional.of(source), Optional.of("198.51.100.20"),
                OptionalInt.of(40000), OptionalInt.of(destinationPort), Protocol.TCP, Optional.empty(), 60,
                Optional.of(new TcpFlags(syn, ack, false, false, false, false)),
                Optional.empty(), Optional.empty());
    }

    private static NetworkPacket icmp(Instant time, String source) {
        return new NetworkPacket(
                time, Optional.of(source), Optional.of("198.51.100.20"),
                OptionalInt.empty(), OptionalInt.empty(), Protocol.ICMP, Optional.empty(), 64,
                Optional.empty(), Optional.empty(), Optional.empty());
    }

    private static NetworkPacket icmpv6(Instant time, String source) {
        return new NetworkPacket(
                time, Optional.of(source), Optional.of("2001:db8::2"),
                OptionalInt.empty(), OptionalInt.empty(), Protocol.ICMPV6, Optional.empty(), 64,
                Optional.empty(), Optional.empty(), Optional.empty());
    }

    private static String findingFingerprint(com.soc.model.IntrusionAlert alert) {
        return alert.timestamp() + "|" + alert.ruleId() + "|" + alert.ruleName() + "|"
                + alert.severity() + "|" + alert.sourceAddress() + "|" + alert.evidence();
    }
}
