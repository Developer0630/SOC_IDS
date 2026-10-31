package com.soc.model;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;

public class AlertModel {
    private final SimpleStringProperty time = new SimpleStringProperty();
    private final SimpleStringProperty srcIp = new SimpleStringProperty();
    private final SimpleIntegerProperty dstPort = new SimpleIntegerProperty();
    private final SimpleStringProperty attackType = new SimpleStringProperty();
    private final SimpleObjectProperty<RiskLevel> riskLevel = new SimpleObjectProperty<>();
    private final SimpleIntegerProperty pps = new SimpleIntegerProperty();
    private final SimpleStringProperty location = new SimpleStringProperty();

    public AlertModel(String time, String srcIp, int dstPort, String attackType, RiskLevel riskLevel, int pps, String location) {
        this.time.set(time);
        this.srcIp.set(srcIp);
        this.dstPort.set(dstPort);
        this.attackType.set(attackType);
        this.riskLevel.set(riskLevel);
        this.pps.set(pps);
        this.location.set(location);
    }

    public String getTime() { return time.get(); }
    public String getSrcIp() { return srcIp.get(); }
    public int getDstPort() { return dstPort.get(); }
    public String getAttackType() { return attackType.get(); }
    public RiskLevel getRiskLevel() { return riskLevel.get(); }
    public int getPps() { return pps.get(); }
    public String getLocation() { return location.get(); }
}