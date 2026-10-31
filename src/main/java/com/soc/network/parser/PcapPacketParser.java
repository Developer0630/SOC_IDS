package com.soc.network.parser;

import com.soc.model.NetworkPacket;
import com.soc.model.Protocol;
import com.soc.model.TcpFlags;
import com.soc.network.capture.PcapPacketRecord;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.util.Optional;
import java.util.OptionalInt;

public final class PcapPacketParser {
    private static final int ETHERNET_LINK_TYPE = 1;
    private static final int ETHERNET_HEADER_LENGTH = 14;

    public PacketParseResult parse(PcapPacketRecord record) {
        if (record.linkType() != ETHERNET_LINK_TYPE) {
            return PacketParseResult.unsupported();
        }
        byte[] data = record.data();
        if (data.length < ETHERNET_HEADER_LENGTH) {
            return PacketParseResult.malformed();
        }

        try {
            DataLinkType linkType = DataLinkType.getInstance(record.linkType());
            Packet packet = PacketFactories.getFactory(Packet.class, DataLinkType.class)
                    .newInstance(data, 0, data.length, linkType);
            if (!packet.contains(IpV4Packet.class) && !packet.contains(IpV6Packet.class)) {
                return PacketParseResult.unsupported();
            }

            Optional<String> source;
            Optional<String> destination;
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ip = packet.get(IpV4Packet.class);
                source = Optional.of(ip.getHeader().getSrcAddr().getHostAddress());
                destination = Optional.of(ip.getHeader().getDstAddr().getHostAddress());
            } else {
                IpV6Packet ip = packet.get(IpV6Packet.class);
                source = Optional.of(ip.getHeader().getSrcAddr().getHostAddress());
                destination = Optional.of(ip.getHeader().getDstAddr().getHostAddress());
            }

            Protocol protocol = Protocol.OTHER;
            OptionalInt sourcePort = OptionalInt.empty();
            OptionalInt destinationPort = OptionalInt.empty();
            Optional<String> dnsQueryName = Optional.empty();
            Optional<TcpFlags> flags = Optional.empty();
            if (packet.contains(TcpPacket.class)) {
                TcpPacket.TcpHeader tcp = packet.get(TcpPacket.class).getHeader();
                sourcePort = OptionalInt.of(tcp.getSrcPort().valueAsInt());
                destinationPort = OptionalInt.of(tcp.getDstPort().valueAsInt());
                flags = Optional.of(new TcpFlags(
                        tcp.getSyn(), tcp.getAck(), tcp.getFin(), tcp.getRst(), tcp.getPsh(), tcp.getUrg()));
                protocol = Protocol.TCP;
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket.UdpHeader udp = packet.get(UdpPacket.class).getHeader();
                sourcePort = OptionalInt.of(udp.getSrcPort().valueAsInt());
                destinationPort = OptionalInt.of(udp.getDstPort().valueAsInt());
                protocol = Protocol.UDP;
                if (packet.contains(DnsPacket.class)) {
                    DnsPacket.DnsHeader dnsHeader = packet.get(DnsPacket.class).getHeader();
                    if (!dnsHeader.isResponse() && !dnsHeader.getQuestions().isEmpty()) {
                        String name = dnsHeader.getQuestions().get(0).getQName().getName();
                        if (name != null && !name.isBlank() && name.length() <= 255) {
                            dnsQueryName = Optional.of(name);
                        }
                    }
                }
            } else if (packet.contains(IcmpV4CommonPacket.class)) {
                protocol = Protocol.ICMP;
            } else if (packet.contains(IcmpV6CommonPacket.class)) {
                protocol = Protocol.ICMPV6;
            }

            Optional<String> sourceMac = Optional.empty();
            Optional<String> destinationMac = Optional.empty();
            if (packet.contains(EthernetPacket.class)) {
                EthernetPacket.EthernetHeader ethernet = packet.get(EthernetPacket.class).getHeader();
                sourceMac = Optional.of(ethernet.getSrcAddr().toString());
                destinationMac = Optional.of(ethernet.getDstAddr().toString());
            }

            NetworkPacket normalized = new NetworkPacket(
                    record.timestamp(), source, destination, sourcePort, destinationPort,
                    protocol, dnsQueryName, record.originalLength(), flags, sourceMac, destinationMac);
            return PacketParseResult.parsed(normalized);
        } catch (RuntimeException exception) {
            return PacketParseResult.malformed();
        }
    }
}
