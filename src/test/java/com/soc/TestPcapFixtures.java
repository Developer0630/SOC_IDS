package com.soc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class TestPcapFixtures {
    private TestPcapFixtures() {
    }

    public static byte[] tcpFrame(int sourcePort, int destinationPort, int flags) {
        byte[] frame = ethernetFrame(0x0800, 40);
        int ip = 14;
        frame[ip] = 0x45;
        putShort(frame, ip + 2, 40);
        frame[ip + 8] = 64;
        frame[ip + 9] = 6;
        frame[ip + 12] = (byte) 192;
        frame[ip + 13] = 0;
        frame[ip + 14] = 2;
        frame[ip + 15] = 10;
        frame[ip + 16] = (byte) 198;
        frame[ip + 17] = 51;
        frame[ip + 18] = 100;
        frame[ip + 19] = 20;

        int tcp = ip + 20;
        putShort(frame, tcp, sourcePort);
        putShort(frame, tcp + 2, destinationPort);
        frame[tcp + 12] = 0x50;
        frame[tcp + 13] = (byte) flags;
        putShort(frame, tcp + 14, 4096);
        return frame;
    }

    public static byte[] udpIpv6Frame(int sourcePort, int destinationPort) {
        byte[] frame = ethernetFrame(0x86DD, 48);
        int ip = 14;
        frame[ip] = 0x60;
        putShort(frame, ip + 4, 8);
        frame[ip + 6] = 17;
        frame[ip + 7] = 64;
        frame[ip + 8] = 0x20;
        frame[ip + 9] = 0x01;
        frame[ip + 23] = 1;
        frame[ip + 24] = 0x20;
        frame[ip + 25] = 0x01;
        frame[ip + 39] = 2;
        int udp = ip + 40;
        putShort(frame, udp, sourcePort);
        putShort(frame, udp + 2, destinationPort);
        putShort(frame, udp + 4, 8);
        return frame;
    }

    public static byte[] icmpv6Frame() {
        byte[] frame = udpIpv6Frame(53000, 53);
        frame[20] = 58;
        frame[54] = (byte) 128;
        return frame;
    }

    public static byte[] arpFrame() {
        return ethernetFrame(0x0806, 28);
    }

    public static byte[] icmpFrame() {
        byte[] frame = ethernetFrame(0x0800, 28);
        int ip = 14;
        frame[ip] = 0x45;
        putShort(frame, ip + 2, 28);
        frame[ip + 8] = 64;
        frame[ip + 9] = 1;
        frame[ip + 12] = (byte) 192;
        frame[ip + 13] = 0;
        frame[ip + 14] = 2;
        frame[ip + 15] = 10;
        frame[ip + 16] = (byte) 198;
        frame[ip + 17] = 51;
        frame[ip + 18] = 100;
        frame[ip + 19] = 20;
        frame[ip + 20] = 8;
        frame[ip + 21] = 0;
        return frame;
    }

    public static byte[] dnsQueryFrame(String domain) {
        byte[] name = dnsName(domain);
        int dnsLength = 12 + name.length + 4;
        byte[] frame = ethernetFrame(0x0800, 20 + 8 + dnsLength);
        int ip = 14;
        frame[ip] = 0x45;
        putShort(frame, ip + 2, 20 + 8 + dnsLength);
        frame[ip + 8] = 64;
        frame[ip + 9] = 17;
        frame[ip + 12] = (byte) 192;
        frame[ip + 13] = 0;
        frame[ip + 14] = 2;
        frame[ip + 15] = 10;
        frame[ip + 16] = (byte) 198;
        frame[ip + 17] = 51;
        frame[ip + 18] = 100;
        frame[ip + 19] = 20;
        int udp = ip + 20;
        putShort(frame, udp, 53000);
        putShort(frame, udp + 2, 53);
        putShort(frame, udp + 4, 8 + dnsLength);
        int dns = udp + 8;
        putShort(frame, dns, 0x1234);
        putShort(frame, dns + 2, 0x0100);
        putShort(frame, dns + 4, 1);
        System.arraycopy(name, 0, frame, dns + 12, name.length);
        putShort(frame, dns + 12 + name.length, 1);
        putShort(frame, dns + 14 + name.length, 1);
        return frame;
    }

    public static byte[] truncatedFrame() {
        return new byte[]{0, 1, 2, 3, 4};
    }

    public static Path writeCapture(Path path, byte[]... frames) throws IOException {
        int total = 24;
        for (byte[] frame : frames) {
            total += 16 + frame.length;
        }
        ByteBuffer data = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        data.put(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        data.putShort((short) 2).putShort((short) 4);
        data.putInt(0).putInt(0).putInt(65535).putInt(1);
        long second = 1_700_000_000L;
        int fraction = 123_456;
        for (byte[] frame : frames) {
            data.putInt((int) second).putInt(fraction++);
            data.putInt(frame.length).putInt(frame.length).put(frame);
        }
        Files.write(path, data.array());
        return path;
    }

    private static byte[] ethernetFrame(int etherType, int payloadLength) {
        byte[] frame = new byte[14 + payloadLength];
        for (int i = 0; i < 6; i++) {
            frame[i] = (byte) (0x10 + i);
            frame[6 + i] = (byte) (0xA0 + i);
        }
        putShort(frame, 12, etherType);
        return frame;
    }

    private static void putShort(byte[] target, int offset, int value) {
        target[offset] = (byte) (value >>> 8);
        target[offset + 1] = (byte) value;
    }

    private static byte[] dnsName(String domain) {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        for (String label : domain.split("\\.")) {
            output.write(label.length());
            output.writeBytes(label.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        output.write(0);
        return output.toByteArray();
    }
}
