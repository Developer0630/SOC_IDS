package com.soc.ui.controller;

import com.soc.core.NidsEngine;
import com.soc.model.AlertModel;
import com.soc.service.FirewallService;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Alert;

public class MainDashboardController {

    private final ObservableList<AlertModel> alertList = FXCollections.observableArrayList();
    private final FirewallService firewallService = new FirewallService();
    private NidsEngine nidsEngine;

    public ObservableList<AlertModel> getAlertList() {
        return alertList;
    }

    // THÊM HÀM NÀY
    public void setNidsEngine(NidsEngine nidsEngine) {
        this.nidsEngine = nidsEngine;
    }

    public void handleBlockIp(AlertModel selectedAlert) {
        if (selectedAlert == null) {
            showAlert(Alert.AlertType.WARNING, "Chưa chọn IP", "Vui lòng chọn 1 dòng trong bảng!");
            return;
        }
        boolean success = firewallService.blockIp(selectedAlert.getSrcIp());
        if (success) {
            if (nidsEngine != null) nidsEngine.addBlockedIp(selectedAlert.getSrcIp());
            showAlert(Alert.AlertType.INFORMATION, "Thành công", "Đã chặn IP: " + selectedAlert.getSrcIp());
        } else {
            showAlert(Alert.AlertType.ERROR, "Lỗi", "Không thể chặn IP. Vui lòng chạy App bằng Run as Administrator!");
        }
    }

    public void handleUnblockIp(AlertModel selectedAlert) {
        if (selectedAlert == null) {
            showAlert(Alert.AlertType.WARNING, "Chưa chọn IP", "Vui lòng chọn 1 dòng trong bảng!");
            return;
        }
        boolean success = firewallService.unblockIp(selectedAlert.getSrcIp());
        if (success) {
            if (nidsEngine != null) nidsEngine.removeBlockedIp(selectedAlert.getSrcIp());
            showAlert(Alert.AlertType.INFORMATION, "Thành công", "Đã mở chặn IP: " + selectedAlert.getSrcIp());
        } else {
            showAlert(Alert.AlertType.ERROR, "Lỗi", "Không thể gỡ luật chặn trên Firewall!");
        }
    }

    private void showAlert(Alert.AlertType type, String title, String content) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }
}