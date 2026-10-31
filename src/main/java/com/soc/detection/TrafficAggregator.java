package com.soc.detection;

import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;
import com.soc.model.TcpFlags;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;

public final class TrafficAggregator {
    private static final int DEFAULT_MAX_SOURCES = 10_000;
    private static final int DEFAULT_MAX_TIME_BUCKETS_PER_SOURCE = 4096;
    private static final int DEFAULT_MAX_TOTAL_BUCKETS = 100_000;

    private final Duration retention;
    private final int maxSources;
    private final int maxBucketsPerSource;
    private final int maxTotalBuckets;
    private final LinkedHashMap<String, SourceState> sources = new LinkedHashMap<>(16, 0.75f, true);
    private long latePacketsDropped;
    private int totalBuckets;

    public TrafficAggregator(Duration retention) {
        this(retention, DEFAULT_MAX_SOURCES, DEFAULT_MAX_TIME_BUCKETS_PER_SOURCE, DEFAULT_MAX_TOTAL_BUCKETS);
    }

    public TrafficAggregator(Duration retention, int maxSources, int maxBucketsPerSource) {
        this(retention, maxSources, maxBucketsPerSource, DEFAULT_MAX_TOTAL_BUCKETS);
    }

    public TrafficAggregator(Duration retention, int maxSources, int maxBucketsPerSource, int maxTotalBuckets) {
        this.retention = Objects.requireNonNull(retention, "retention");
        if (retention.isZero() || retention.isNegative() || maxSources <= 0
                || maxBucketsPerSource <= 0 || maxTotalBuckets <= 0) {
            throw new IllegalArgumentException("Aggregation limits must be positive");
        }
        this.maxSources = maxSources;
        this.maxBucketsPerSource = maxBucketsPerSource;
        this.maxTotalBuckets = maxTotalBuckets;
    }

    public void record(NetworkPacket packet) {
        Objects.requireNonNull(packet, "packet");
        Optional<String> source = packet.sourceAddress();
        if (source.isEmpty()) {
            return;
        }

        SourceState state = sources.get(source.get());
        if (state == null) {
            if (sources.size() == maxSources) {
                String eldestSource = sources.keySet().iterator().next();
                removeSource(eldestSource);
            }
            state = new SourceState();
            sources.put(source.get(), state);
        }
        if (state.latestTimestamp != null
                && packet.timestamp().isBefore(state.latestTimestamp.minus(retention))) {
            latePacketsDropped++;
            return;
        }
        if (state.latestTimestamp == null || packet.timestamp().isAfter(state.latestTimestamp)) {
            state.latestTimestamp = packet.timestamp();
        }

        Instant cutoff = state.latestTimestamp.minus(retention);
        int expiredBuckets = state.buckets.headMap(cutoff, false).size();
        state.buckets.headMap(cutoff, false).clear();
        totalBuckets -= expiredBuckets;
        Bucket bucket = state.buckets.get(packet.timestamp());
        if (bucket == null) {
            ensureBucketCapacity(source.get(), state);
            bucket = new Bucket();
            state.buckets.put(packet.timestamp(), bucket);
            totalBuckets++;
        }
        bucket.packetCount++;
        bucket.byteCount += packet.packetLength();
        if (packet.protocol() == Protocol.TCP) {
            if (packet.destinationPort().isPresent()) {
                bucket.tcpDestinationPorts.add(packet.destinationPort().getAsInt());
            }
            if (packet.tcpFlags().filter(TcpFlags::syn).filter(flags -> !flags.ack()).isPresent()) {
                bucket.bareSynCount++;
            }
        } else if (packet.protocol() == Protocol.ICMP || packet.protocol() == Protocol.ICMPV6) {
            bucket.icmpPacketCount++;
        }
        while (state.buckets.size() > maxBucketsPerSource) {
            state.buckets.pollFirstEntry();
            totalBuckets--;
        }
    }

    public TrafficWindowSnapshot snapshot(String sourceAddress, Instant eventTime, Duration window) {
        Objects.requireNonNull(sourceAddress, "sourceAddress");
        Objects.requireNonNull(eventTime, "eventTime");
        Objects.requireNonNull(window, "window");
        if (window.isZero() || window.isNegative() || window.compareTo(retention) > 0) {
            throw new IllegalArgumentException("Requested window exceeds aggregator retention");
        }
        SourceState state = sources.get(sourceAddress);
        if (state == null) {
            return new TrafficWindowSnapshot(0, 0, 0, 0, 0);
        }

        Instant start = eventTime.minus(window);
        long packets = 0;
        long bytes = 0;
        long syns = 0;
        long icmp = 0;
        TreeSet<Integer> ports = new TreeSet<>();
        for (Bucket bucket : state.buckets.subMap(start, true, eventTime, true).values()) {
            packets += bucket.packetCount;
            bytes += bucket.byteCount;
            syns += bucket.bareSynCount;
            icmp += bucket.icmpPacketCount;
            ports.addAll(bucket.tcpDestinationPorts);
        }
        return new TrafficWindowSnapshot(packets, bytes, ports.size(), syns, icmp);
    }

    public int trackedSourceCount() {
        return sources.size();
    }

    public long latePacketsDropped() {
        return latePacketsDropped;
    }

    public void clear() {
        sources.clear();
        latePacketsDropped = 0;
        totalBuckets = 0;
    }

    private void ensureBucketCapacity(String currentSource, SourceState currentState) {
        if (totalBuckets < maxTotalBuckets) {
            return;
        }
        for (Map.Entry<String, SourceState> entry : sources.entrySet()) {
            if (!entry.getKey().equals(currentSource) && !entry.getValue().buckets.isEmpty()) {
                removeSource(entry.getKey());
                return;
            }
        }
        if (!currentState.buckets.isEmpty()) {
            currentState.buckets.pollFirstEntry();
            totalBuckets--;
        }
    }

    private void removeSource(String sourceAddress) {
        SourceState removed = sources.remove(sourceAddress);
        if (removed != null) {
            totalBuckets -= removed.buckets.size();
        }
    }

    private static final class SourceState {
        private final NavigableMap<Instant, Bucket> buckets = new TreeMap<>();
        private Instant latestTimestamp;
    }

    private static final class Bucket {
        private long packetCount;
        private long byteCount;
        private long bareSynCount;
        private long icmpPacketCount;
        private final TreeSet<Integer> tcpDestinationPorts = new TreeSet<>();
    }
}
