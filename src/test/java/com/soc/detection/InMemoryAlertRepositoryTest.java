package com.soc.detection;

import com.soc.model.AlertStatus;
import com.soc.model.IntrusionAlert;
import com.soc.model.RiskLevel;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InMemoryAlertRepositoryTest {
    @Test
    void retainsOnlyTheMostRecentConfiguredNumberOfAlerts() {
        InMemoryAlertRepository repository = new InMemoryAlertRepository(2);
        IntrusionAlert first = alert(Instant.parse("2025-01-01T00:00:00Z"));
        IntrusionAlert second = alert(Instant.parse("2025-01-01T00:00:01Z"));
        IntrusionAlert third = alert(Instant.parse("2025-01-01T00:00:02Z"));

        repository.saveAll(List.of(first, second, third));

        assertEquals(List.of(second, third), repository.findAll());
    }

    private static IntrusionAlert alert(Instant timestamp) {
        return new IntrusionAlert(
                UUID.randomUUID(), timestamp, Optional.empty(), Optional.empty(),
                "TEST", RiskLevel.LOW, "Synthetic unit-test alert", "Synthetic evidence",
                AlertStatus.NEW, UUID.randomUUID());
    }
}
