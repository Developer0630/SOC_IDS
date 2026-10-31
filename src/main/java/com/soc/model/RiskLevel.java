package com.soc.model;

public enum RiskLevel {
    LOW("#2563EB"),
    MEDIUM("#D97706"),
    HIGH("#EA580C"),
    CRITICAL("#DC2626");

    private final String colorHex;
    RiskLevel(String colorHex) { this.colorHex = colorHex; }
    public String getColorHex() { return colorHex; }
}