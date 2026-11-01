package com.soc;

import javafx.fxml.FXMLLoader;
import javafx.application.Application;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.stage.Stage;
import com.soc.ui.controller.MainDashboardController;
import com.soc.detection.DetectionRuleSettings;
import com.soc.persistence.ImportPersistence;
import com.soc.persistence.MySqlDatabase;
import com.soc.persistence.MySqlImportPersistence;
import com.soc.persistence.PersistenceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class MainApp extends Application {
    private static final Logger LOGGER = LoggerFactory.getLogger(MainApp.class);
    private MainDashboardController dashboardController;
    private ImportPersistence persistence;
    private DetectionRuleSettings ruleSettings = DetectionRuleSettings.defaults();
    private String persistenceFailure;

    @Override
    public void init() {
        try {
            MySqlDatabase database = MySqlDatabase.fromEnvironment();
            database.initialize();
            MySqlImportPersistence mysqlPersistence = new MySqlImportPersistence(database);
            mysqlPersistence.markRunningImportsInterrupted();
            ruleSettings = mysqlPersistence.loadOrCreateRuleSettings();
            persistence = mysqlPersistence;
        } catch (PersistenceException exception) {
            persistenceFailure = exception.getMessage();
            LOGGER.error("MySQL persistence is unavailable; imports will be disabled", exception);
        }
    }

    @Override
    public void start(Stage primaryStage) {
        Parent root;
        try {
            FXMLLoader loader = new FXMLLoader(MainApp.class.getResource("/com/soc/ui/view/MainDashboard.fxml"));
            loader.setControllerFactory(controllerType -> {
                if (controllerType == MainDashboardController.class) {
                    return new MainDashboardController(persistence, ruleSettings, persistenceFailure);
                }
                throw new IllegalStateException("Unsupported FXML controller: " + controllerType.getName());
            });
            root = loader.load();
            dashboardController = loader.getController();
        } catch (IOException | RuntimeException exception) {
            LOGGER.error("Unable to load the main application view", exception);
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Startup error");
            alert.setHeaderText("Sentinel NOC could not start");
            alert.setContentText("The application interface could not be loaded. See the application log for details.");
            alert.showAndWait();
            throw new IllegalStateException("Unable to load the main application view", exception);
        }

        Scene scene = new Scene(root, 1280, 800);
        scene.getStylesheets().add(MainApp.class.getResource("/com/soc/ui/css/light.css").toExternalForm());
        primaryStage.setTitle("Sentinel NOC - Network Intrusion Detection System");
        primaryStage.setMinWidth(1000);
        primaryStage.setMinHeight(650);
        primaryStage.setScene(scene);
        primaryStage.show();
        LOGGER.info("Sentinel NOC application started");
    }

    @Override
    public void stop() {
        if (dashboardController != null) {
            dashboardController.shutdown();
        }
        LOGGER.info("Sentinel NOC application stopped");
    }

    public static void main(String[] args) {
        launch(args);
    }
}