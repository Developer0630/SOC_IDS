package com.soc.core;

import com.soc.model.AlertModel;
import javafx.application.Platform;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class NidsEngine implements Runnable {
    private PcapHandle handle;
    private boolean running = true;
    private final Consumer<AlertModel> alertCallback;
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet(); // THÊM BIẾN NÀY
    private final Set<String> internalSubnets = Set.of("192.168.", "10.", "172.16.");
    private int thresholdPps = 10;

    private final Map<String, IpTracker> trackerMap = new HashMap<>();

    public NidsEngine(PcapNetworkInterface nif, Consumer<AlertModel> alertCallback) throws PcapNativeException {
        this.alertCallback = alertCallback;
        int snapshotLength = 65536;
        int timeout = 10;
        this.handle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
    }

    public void setThresholdPps(int threshold) { this.thresholdPps = threshold; }
    public void addWhitelistIp(String ip) { if (ip != null && !ip.isEmpty()) whitelist.add(ip.trim()); }
    
    // THÊM 2 HÀM NÀY ĐỂ FIX LỖI Controller
    public void addBlockedIp(String ip) { if (ip != null && !ip.isEmpty()) blockedIps.add(ip.trim()); }
    public void removeBlockedIp(String ip) { if (ip != null) blockedIps.remove(ip.trim()); }

    public void stop() { this.running = false; if (handle != null) handle.close(); }

    @Override
    public void run() {
        long lastResetTime = System.currentTimeMillis();

        while (running) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet == null) continue;

                long currentTime = System.currentTimeMillis();

                if (currentTime - lastResetTime >= 1000) {
                    evaluateAndAlert();
                    trackerMap.clear();
                    lastResetTime = currentTime;
                }

                if (packet.contains(IpV4Packet.class) && packet.contains(TcpPacket.class)) {
                    IpV4Packet ipPkt = packet.get(IpV4Packet.class);
                    TcpPacket tcpPkt = packet.get(TcpPacket.class);

                    String srcIp = ipPkt.getHeader().getSrcAddr().getHostAddress();
                    int dstPort = tcpPkt.getHeader().getDstPort().valueAsInt();
                    boolean isSyn = tcpPkt.getHeader().getSyn();

                    // Bỏ qua Whitelist và các IP đã bị Block
                    if (whitelist.contains(srcIp) || blockedIps.contains(srcIp)) continue;

                    IpTracker tracker = trackerMap.computeIfAbsent(srcIp, k -> new IpTracker());
                    tracker.totalPackets++;
                    tracker.dstPorts.add(dstPort);
                    if (isSyn) tracker.synCount++;
                    tracker.lastDstPort = dstPort;
                }

            } catch (Exception e) {
                // Ignore capture errors
            }
        }
    }

    private void evaluateAndAlert() {
        for (Map.Entry<String, IpTracker> entry : trackerMap.entrySet()) {
            String srcIp = entry.getKey();
            IpTracker tracker = entry.getValue();

            if (tracker.totalPackets >= thresholdPps) {
                int uniquePorts = tracker.dstPorts.size();
                boolean isSynOnly = tracker.synCount > 0;

                // FIX LỖI KHOẢNG [103,36]: Dùng ThreatAnalyzer để tạo AlertModel chuẩn tham số
                AlertModel alert = ThreatAnalyzer.analyze(srcIp, tracker.totalPackets, uniquePorts, isSynOnly, internalSubnets);

                if (alert != null) {
                    Platform.runLater(() -> alertCallback.accept(alert));
                }
            }
        }
    }

    private static class IpTracker {
        int totalPackets = 0;
        int synCount = 0;
        int lastDstPort = 0;
        Set<Integer> dstPorts = new HashSet<>();
    }
}