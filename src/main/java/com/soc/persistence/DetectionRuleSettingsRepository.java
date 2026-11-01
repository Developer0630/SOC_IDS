package com.soc.persistence;

import com.soc.detection.DetectionRuleSettings;

public interface DetectionRuleSettingsRepository {
    DetectionRuleSettings loadOrCreateRuleSettings();

    void saveRuleSettings(DetectionRuleSettings settings);
}
