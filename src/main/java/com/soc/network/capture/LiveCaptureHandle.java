package com.soc.network.capture;

public interface LiveCaptureHandle extends AutoCloseable {
    void loop() throws Exception;

    void stop();

    @Override
    void close();
}
