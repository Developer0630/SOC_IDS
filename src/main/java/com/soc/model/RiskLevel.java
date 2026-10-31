package com.soc.model;

public enum RiskLevel {
    LOW("#10b981"),      // Xanh lá: Traffic nội bộ / Khách hàng
    MEDIUM("#f59e0b"),   // Vàng: Hành vi nghi vấn
    HIGH("#ef4444"),     // Đỏ: Port Scan / Tấn công rõ ràng
    CRITICAL("#7c3aed"); // Tím: SYN Flood DDoS / IP Botnet đen

    private final String colorHex;
    RiskLevel(String colorHex) { this.colorHex = colorHex; }
    public String getColorHex() { return colorHex; }
}