package com.soc.core;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;

import com.soc.model.AlertModel;
import com.soc.model.RiskLevel;

public class ThreatAnalyzer {

    public static AlertModel analyze(String srcIp, int pps, int uniquePorts, boolean isSynOnly, Set<String> internalSubnets) {
        String nowStr = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        
        // 1. Kiểm tra xem có phải IP Mạng nội bộ (Nhân viên IT / Dev)
        boolean isInternal = internalSubnets.stream().anyMatch(srcIp::startsWith);
        String location = isInternal ? "Internal LAN" : "External IP";

        // 2. Tính toán loại tấn công & Mức độ Rủi ro
        String attackType;
        RiskLevel risk;

        if (uniquePorts >= 10) {
            attackType = "PORT SCAN";
            risk = isInternal ? RiskLevel.MEDIUM : RiskLevel.HIGH; // Nội bộ quét = Medium, Bên ngoài = High
        } else if (uniquePorts <= 3 && isSynOnly) {
            attackType = "SYN FLOOD (DDOS)";
            risk = RiskLevel.CRITICAL; // SYN Flood luôn là Critical
        } else {
            attackType = "SUSPICIOUS TRAFFIC";
            risk = RiskLevel.LOW;
        }

        return new AlertModel(nowStr, srcIp, 80, attackType, risk, pps, location);
    }
}