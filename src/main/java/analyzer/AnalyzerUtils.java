package analyzer;

import entity.InterfaceModel;
import entity.PacketModel;
import entity.PortModel;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AnalyzerUtils {
    public static List<InterfaceModel> getAllNetworkInterfacesName() throws PcapNativeException {
        List<PcapNetworkInterface> allInterFace = Pcaps.findAllDevs();
        List<InterfaceModel> interfaceModels = new ArrayList<>();
        int id = 0;
        for (PcapNetworkInterface networkInterface : allInterFace) {
            interfaceModels.add(new InterfaceModel(id++, networkInterface.getName()));
        }
        return interfaceModels;
    }

    public static PacketModel convert(Packet packet, long id) {
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            long date = getTime();
            int size = packet.length();
            String descriptor = packet.toString();
            String srcMac = ethernetPacket.getHeader().getSrcAddr().toString();
            String dstMac = ethernetPacket.getHeader().getDstAddr().toString();

            String protocol;
            String srcIp;
            String dstIp;

            PortModel srcPort;
            PortModel dstPort;
            String extInfo;

            if (EtherType.IPV4.equals(ethernetPacket.getHeader().getType())) {
                IpV4Packet ipv4 = ethernetPacket.getPayload().get(IpV4Packet.class);
                protocol = ipv4.getHeader().getProtocol().name();
                srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
                dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
                if (IpNumber.TCP.equals(ipv4.getHeader().getProtocol())) {
                    TcpPacket tcp = ipv4.getPayload().get(TcpPacket.class);
                    srcPort = new PortModel(tcp.getHeader().getSrcPort().valueAsInt(), tcp.getHeader().getSrcPort().name());
                    dstPort = new PortModel(tcp.getHeader().getDstPort().valueAsInt(), tcp.getHeader().getDstPort().name());
                    extInfo = tcp.getPayload().toString();
                } else if (IpNumber.UDP.equals(ipv4.getHeader().getProtocol())) {
                    UdpPacket udp = ipv4.getPayload().get(UdpPacket.class);
                    srcPort = new PortModel(udp.getHeader().getSrcPort().valueAsInt(), udp.getHeader().getSrcPort().name());
                    dstPort = new PortModel(udp.getHeader().getDstPort().valueAsInt(), udp.getHeader().getDstPort().name());
                    extInfo = udp.getPayload().toString();
                } else if (IpNumber.ICMPV4.equals(ipv4.getHeader().getProtocol())) {
                    IcmpV4CommonPacket icmp = ipv4.getPayload().get(IcmpV4CommonPacket.class);
                    srcPort = null;
                    dstPort = null;
                    extInfo = "type: " + icmp.getHeader().getType().toString() + " / code: " + icmp.getHeader().getCode().toString() + "\n" + icmp.getPayload().toString();
                } else if (IpNumber.IGMP.equals(ipv4.getHeader().getProtocol())) {
                    //TODO: Find new way to handle IGMP packets
                    srcPort = null;
                    dstPort = null;
                    extInfo = ipv4.getPayload().toString();
                } else {
                    srcPort = null;
                    dstPort = null;
                    extInfo = ipv4.getPayload().toString();
                }
            } else if (EtherType.IPV6.equals(ethernetPacket.getHeader().getType())) {
                IpV6Packet ipv6 = ethernetPacket.getPayload().get(IpV6Packet.class);
                protocol = ipv6.getHeader().getProtocol().name();
                srcIp = ipv6.getHeader().getSrcAddr().getHostAddress();
                dstIp = ipv6.getHeader().getDstAddr().getHostAddress();
                if (IpNumber.TCP.equals(ipv6.getHeader().getProtocol())) {
                    TcpPacket tcp = ipv6.getPayload().get(TcpPacket.class);
                    srcPort = new PortModel(tcp.getHeader().getSrcPort().valueAsInt(), tcp.getHeader().getSrcPort().name());
                    dstPort = new PortModel(tcp.getHeader().getDstPort().valueAsInt(), tcp.getHeader().getDstPort().name());
                    extInfo = tcp.getPayload().toString();
                } else if (IpNumber.UDP.equals(ipv6.getHeader().getProtocol())) {
                    UdpPacket udp = ipv6.getPayload().get(UdpPacket.class);
                    srcPort = new PortModel(udp.getHeader().getSrcPort().valueAsInt(), udp.getHeader().getSrcPort().name());
                    dstPort = new PortModel(udp.getHeader().getDstPort().valueAsInt(), udp.getHeader().getDstPort().name());
                    extInfo = udp.getPayload().toString();
                } else if (IpNumber.ICMPV6.equals(ipv6.getHeader().getProtocol())) {
                    IcmpV6CommonPacket icmp = ipv6.getPayload().get(IcmpV6CommonPacket.class);
                    srcPort = null;
                    dstPort = null;
                    extInfo = "type: " + icmp.getHeader().getType().toString() + " / code: " + icmp.getHeader().getCode().toString() + "\n" + icmp.getPayload().toString();
                } else {
                    srcPort = null;
                    dstPort = null;
                    extInfo = ipv6.getPayload().toString();
                }
            } else if (EtherType.ARP.equals(ethernetPacket.getHeader().getType())) {
                protocol = EtherType.ARP.name();
                ArpPacket arp = ethernetPacket.getPayload().get(ArpPacket.class);
                srcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                srcMac = arp.getHeader().getSrcHardwareAddr().toString();
                dstIp = arp.getHeader().getDstProtocolAddr().getHostAddress();
                dstMac = arp.getHeader().getDstHardwareAddr().toString();
                srcPort = null;
                dstPort = null;
                extInfo = "operation: " + arp.getHeader().getOperation().name() + "\n" + arp.getPayload();
//            } else if (EtherType.RARP.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.DOT1Q_VLAN_TAGGED_FRAMES.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.APPLETALK.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.PPP.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.MPLS.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.PPPOE_DISCOVERY_STAGE.equals(ethernetPacket.getHeader().getType())) {
//            } else if (EtherType.PPPOE_SESSION_STAGE.equals(ethernetPacket.getHeader().getType())) {
            } else {
                protocol = ethernetPacket.getHeader().getType().name();
                srcIp = "";
                dstIp = "";
                srcPort = null;
                dstPort = null;
                extInfo = ethernetPacket.toString();
            }
            return new PacketModel(
                    id,
                    date,
                    size,
                    protocol,
                    srcMac,
                    srcIp,
                    srcPort,
                    dstMac,
                    dstIp,
                    dstPort,
                    extInfo,
                    descriptor
            );
        }
        return null;
    }

    private static long getTime() {
        return new Date().getTime();
    }
}
