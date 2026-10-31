package com.soc;

import com.soc.ui.controller.MainDashboardController;
import com.soc.ui.view.MainDashboardView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) {
        // Khởi tạo MVC
        MainDashboardController controller = new MainDashboardController();
        MainDashboardView view = new MainDashboardView(controller);

        Scene scene = new Scene(view.getRootLayout(), 1000, 600);
        primaryStage.setTitle("SOC NIDS Desktop Command Center");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}