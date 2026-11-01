package com.soc.network.capture;

import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

public interface LivePacketSource {
    List<LiveCaptureInterface> listInterfaces() throws IOException;

    LiveCaptureHandle open(String interfaceName, Consumer<LiveCapturedPacket> packetConsumer)
            throws IOException;
}
