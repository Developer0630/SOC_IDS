package com.soc.detection;

import com.soc.model.IntrusionAlert;

import java.util.List;

public interface AlertRepository {
    void saveAll(List<IntrusionAlert> alerts);

    List<IntrusionAlert> findAll();
}
