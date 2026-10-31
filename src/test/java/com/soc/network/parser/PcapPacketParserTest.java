package com.soc.network.parser;

import com.soc.TestPcapFixtures;
import com.soc.model.Protocol;
import com.soc.network.capture.PcapPacketRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PcapPacketParserTest {
    private final PcapPacketParser parser = new PcapPacketParser();

    @Test
    void normalizesIpv4TcpMetadataAndFlags() {
        byte[] frame = TestPcapFixtures.tcpFrame(49152, 443, 0x12);
        Instant timestamp = Instant.parse("2023-11-14T22:13:20.123456Z");

        PacketParseResult result = parser.parse(new PcapPacketRecord(timestamp, frame, 1, frame.length));

        assertEquals(PacketParseResult.Status.PARSED, result.status());
        var packet = result.packet().orElseThrow();
        assertEquals(timestamp, packet.timestamp());
        assertEquals("192.0.2.10", packet.sourceAddress().orElseThrow());
        assertEquals("198.51.100.20", packet.destinationAddress().orElseThrow());
        assertEquals(49152, packet.sourcePort().orElseThrow());
        assertEquals(443, packet.destinationPort().orElseThrow());
        assertEquals(Protocol.TCP, packet.protocol());
        assertTrue(packet.tcpFlags().orElseThrow().syn());
        assertTrue(packet.tcpFlags().orElseThrow().ack());
        assertEquals(54, packet.packetLength());
        assertTrue(packet.sourceMac().isPresent());
    }

    @Test
    void normalizesIpv6UdpWithoutTcpFlags() {
        byte[] frame = TestPcapFixtures.udpIpv6Frame(53000, 53);
        PacketParseResult result = parser.parse(
                new PcapPacketRecord(Instant.EPOCH, frame, 1, frame.length));

        var packet = result.packet().orElseThrow();
        assertEquals("2001:0:0:0:0:0:0:1", packet.sourceAddress().orElseThrow());
        assertEquals(Protocol.UDP, packet.protocol());
        assertEquals(53000, packet.sourcePort().orElseThrow());
        assertEquals(53, packet.destinationPort().orElseThrow());
        assertTrue(packet.tcpFlags().isEmpty());
    }

    @Test
    void extractsDnsQuestionOnlyFromParsedDnsQueries() {
        byte[] frame = TestPcapFixtures.dnsQueryFrame("example.com");

        var packet = parser.parse(new PcapPacketRecord(Instant.EPOCH, frame, 1, frame.length))
                .packet().orElseThrow();

        assertEquals(Protocol.UDP, packet.protocol());
        assertEquals("example.com", packet.dnsQueryName().orElseThrow());
    }

    @Test
    void classifiesIcmpWithoutInventingPortNumbers() {
        byte[] frame = TestPcapFixtures.icmpFrame();

        var packet = parser.parse(new PcapPacketRecord(Instant.EPOCH, frame, 1, frame.length))
                .packet().orElseThrow();

        assertEquals(Protocol.ICMP, packet.protocol());
        assertTrue(packet.sourcePort().isEmpty());
        assertTrue(packet.destinationPort().isEmpty());
    }

    @Test
    void classifiesIcmpv6() {
        byte[] frame = TestPcapFixtures.icmpv6Frame();

        var packet = parser.parse(new PcapPacketRecord(Instant.EPOCH, frame, 1, frame.length))
                .packet().orElseThrow();

        assertEquals(Protocol.ICMPV6, packet.protocol());
        assertTrue(packet.sourcePort().isEmpty());
        assertTrue(packet.destinationPort().isEmpty());
    }

    @Test
    void marksNonIpAndUnsupportedLinkLayersAsUnsupported() {
        byte[] arp = TestPcapFixtures.arpFrame();
        assertEquals(PacketParseResult.Status.UNSUPPORTED,
                parser.parse(new PcapPacketRecord(Instant.EPOCH, arp, 1, arp.length)).status());
        assertEquals(PacketParseResult.Status.UNSUPPORTED,
                parser.parse(new PcapPacketRecord(Instant.EPOCH, arp, 999, arp.length)).status());
    }

    @Test
    void marksTruncatedFramesAsMalformedWithoutThrowing() {
        PacketParseResult result = parser.parse(
                new PcapPacketRecord(Instant.EPOCH, TestPcapFixtures.truncatedFrame(), 1, 5));

        assertEquals(PacketParseResult.Status.MALFORMED, result.status());
        assertFalse(result.packet().isPresent());
    }
}
