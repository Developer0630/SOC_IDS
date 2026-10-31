package com.soc.detection;

import com.soc.model.IntrusionAlert;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class InMemoryAlertRepository implements AlertRepository {
    public static final int DEFAULT_CAPACITY = 5000;

    private final int capacity;
    private final ArrayDeque<IntrusionAlert> alerts = new ArrayDeque<>();

    public InMemoryAlertRepository() {
        this(DEFAULT_CAPACITY);
    }

    public InMemoryAlertRepository(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("Alert repository capacity must be positive");
        }
        this.capacity = capacity;
    }

    @Override
    public synchronized void saveAll(List<IntrusionAlert> newAlerts) {
        Objects.requireNonNull(newAlerts, "newAlerts");
        for (IntrusionAlert alert : newAlerts) {
            alerts.addLast(Objects.requireNonNull(alert, "alert"));
            while (alerts.size() > capacity) {
                alerts.removeFirst();
            }
        }
    }

    @Override
    public synchronized List<IntrusionAlert> findAll() {
        return List.copyOf(new ArrayList<>(alerts));
    }
}
