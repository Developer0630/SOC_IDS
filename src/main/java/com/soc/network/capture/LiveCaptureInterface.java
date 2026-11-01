package com.soc.network.capture;

import java.util.List;
import java.util.Objects;

public record LiveCaptureInterface(String name, String description, List<String> addresses) {
    public LiveCaptureInterface {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Capture interface name cannot be blank");
        }
        description = Objects.requireNonNullElse(description, "");
        addresses = List.copyOf(Objects.requireNonNull(addresses, "addresses"));
    }

    @Override
    public String toString() {
        String label = description.isBlank() ? name : description;
        return addresses.isEmpty() ? label + " [" + name + "]"
                : label + " [" + name + "] · " + String.join(", ", addresses);
    }
}
