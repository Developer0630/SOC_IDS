package com.soc.ui.view;

import com.soc.model.AlertModel;
import com.soc.model.RiskLevel;
import com.soc.ui.controller.MainDashboardController;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;

public class MainDashboardView {

    private final MainDashboardController controller;
    private final BorderPane rootLayout = new BorderPane();
    private TableView<AlertModel> table = new TableView<>();

    public MainDashboardView(MainDashboardController controller) {
        this.controller = controller;
        initView();
    }

    private void initView() {
        // Top Toolbar
        HBox topBox = new HBox(15);
        topBox.setPadding(new Insets(10));
        topBox.setStyle("-fx-background-color: #0f172a;");

        Label title = new Label("🛡️ SOC COMMAND CENTER (DISTRIBUTED NIDS)");
        title.setStyle("-fx-text-fill: white; -fx-font-size: 16px; -fx-font-weight: bold;");
        topBox.getChildren().add(title);

        // Center Table View
        setupTable();

        // Bottom Action Bar
        HBox bottomBox = new HBox(10);
        bottomBox.setPadding(new Insets(10));
        bottomBox.setStyle("-fx-background-color: #0f172a;");

        Button blockBtn = new Button("Chặn IP (Block)");
        blockBtn.setStyle("-fx-background-color: #ef4444; -fx-text-fill: white; -fx-font-weight: bold;");
        blockBtn.setOnAction(e -> controller.handleBlockIp(table.getSelectionModel().getSelectedItem()));

        Button unblockBtn = new Button("Mở Chặn IP (Unblock)");
        unblockBtn.setStyle("-fx-background-color: #10b981; -fx-text-fill: white; -fx-font-weight: bold;");
        unblockBtn.setOnAction(e -> controller.handleUnblockIp(table.getSelectionModel().getSelectedItem()));

        bottomBox.getChildren().addAll(blockBtn, unblockBtn);

        rootLayout.setTop(topBox);
        rootLayout.setCenter(table);
        rootLayout.setBottom(bottomBox);
    }

    private void setupTable() {
        TableColumn<AlertModel, String> colTime = new TableColumn<>("Thời gian");
        colTime.setCellValueFactory(new PropertyValueFactory<>("time"));

        TableColumn<AlertModel, String> colIp = new TableColumn<>("IP Nguồn");
        colIp.setCellValueFactory(new PropertyValueFactory<>("srcIp"));

        TableColumn<AlertModel, String> colType = new TableColumn<>("Loại Tấn Công");
        colType.setCellValueFactory(new PropertyValueFactory<>("attackType"));

        TableColumn<AlertModel, RiskLevel> colRisk = new TableColumn<>("Mức Rủi Ro");
        colRisk.setCellValueFactory(new PropertyValueFactory<>("riskLevel"));
        
        // Custom Cell Rendering để tô màu Mức Rủi ro
        colRisk.setCellFactory(column -> new TableCell<>() {
            @Override
            protected void updateItem(RiskLevel item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item.name());
                    setStyle("-fx-background-color: " + item.getColorHex() + "; -fx-text-fill: white; -fx-alignment: CENTER; -fx-font-weight: bold;");
                }
            }
        });

        TableColumn<AlertModel, String> colLoc = new TableColumn<>("Vị Trí / Vùng Mạng");
        colLoc.setCellValueFactory(new PropertyValueFactory<>("location"));

        table.getColumns().addAll(colTime, colIp, colType, colRisk, colLoc);
        table.setItems(controller.getAlertList());
    }

    public Pane getRootLayout() {
        return rootLayout;
    }
}