package analyzer

import entity.PortModel
import entity.PacketModel
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.*
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.packet.namednumber.IpNumber
import java.util.*

class AnalyzerUtils {
    companion object {

        fun getAllNetworkInterfacesName(): List<String> {
            return Pcaps.findAllDevs().map { it.name }
        }

        fun Packet.convert(id: Long): PacketModel? {
            if (contains(EthernetPacket::class.java)) {
                val ethernetPacket = get(EthernetPacket::class.java)
                val date = getTime()
                val size = length()
                val descriptor = toString()
                val srcMac = ethernetPacket.header.srcAddr.toString()
                val dstMac = ethernetPacket.header.dstAddr.toString()

                val protocol: String
                val srcIp: String
                val dstIp: String

                val srcPort: PortModel?
                val dstPort: PortModel?
                val extInfo: String

                when (ethernetPacket.header.type) {
                    EtherType.IPV4 -> {
                        val ipv4 = ethernetPacket.get(IpV4Packet::class.java).header
                        protocol = ipv4.protocol.name()
                        srcIp = ipv4.srcAddr.hostAddress
                        dstIp = ipv4.dstAddr.hostAddress
                        when (ipv4.protocol) {
                            IpNumber.TCP -> {
                                val tcp = ethernetPacket.get(TcpPacket::class.java).header
                                srcPort = PortModel(tcp.srcPort.valueAsInt(), tcp.srcPort.name())
                                dstPort = PortModel(tcp.dstPort.valueAsInt(), tcp.dstPort.name())
                                extInfo = ""
                            }
                            IpNumber.UDP -> {
                                val udp = ethernetPacket.get(UdpPacket::class.java).header
                                srcPort = PortModel(udp.srcPort.valueAsInt(), udp.srcPort.name())
                                dstPort = PortModel(udp.dstPort.valueAsInt(), udp.dstPort.name())
                                extInfo = ""
                            }
                            IpNumber.ICMPV4 -> {
                                val icmp = ethernetPacket.get(IcmpV4CommonPacket::class.java).header
                                srcPort = null
                                dstPort = null
                                extInfo = "${icmp.type} / ${icmp.code}"
                            }
                            IpNumber.IGMP -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ""
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ""
                            }
                        }
                    }
                    EtherType.IPV6 -> {
                        val ipv6 = ethernetPacket.get(IpV6Packet::class.java).header
                        protocol = ipv6.protocol.name()
                        srcIp = ipv6.srcAddr.hostAddress
                        dstIp = ipv6.dstAddr.hostAddress
                        when (ipv6.protocol) {
                            IpNumber.TCP -> {
                                val tcp = ethernetPacket.get(TcpPacket::class.java).header
                                srcPort = PortModel(tcp.srcPort.valueAsInt(), tcp.srcPort.name())
                                dstPort = PortModel(tcp.dstPort.valueAsInt(), tcp.dstPort.name())
                                extInfo = ""
                            }
                            IpNumber.UDP -> {
                                val udp = ethernetPacket.get(UdpPacket::class.java).header
                                srcPort = PortModel(udp.srcPort.valueAsInt(), udp.srcPort.name())
                                dstPort = PortModel(udp.dstPort.valueAsInt(), udp.dstPort.name())
                                extInfo = ""
                            }
                            IpNumber.ICMPV6 -> {
                                val icmp = ethernetPacket.get(IcmpV6CommonPacket::class.java).header
                                srcPort = null
                                dstPort = null
                                extInfo = "${icmp.type} / ${icmp.code}"
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ""
                            }
                        }
                    }
                    EtherType.ARP -> {
                        protocol = EtherType.ARP.name()
                        val arp = ethernetPacket.get(ArpPacket::class.java).header
                        srcIp = arp.srcProtocolAddr.hostAddress
                        dstIp = arp.dstProtocolAddr.hostAddress
                        srcPort = null
                        dstPort = null
                        extInfo = "operation: ${arp.operation.name()}"
                    }
//                    EtherType.RARP -> {
//                    }
//                    EtherType.DOT1Q_VLAN_TAGGED_FRAMES -> {
//                    }
//                    EtherType.APPLETALK -> {
//                    }
//                    EtherType.PPP -> {
//                    }
//                    EtherType.MPLS -> {
//                    }
//                    EtherType.PPPOE_DISCOVERY_STAGE -> {
//                    }
//                    EtherType.PPPOE_SESSION_STAGE -> {
//                    }
                    else -> {
                        protocol = EtherType.ARP.name()
                        srcIp = ""
                        dstIp = ""
                        srcPort = null
                        dstPort = null
                        extInfo = ""
                    }
                }
                return PacketModel(
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
                )
            }
            return null
        }

        private fun getTime(): Long {
            return Date().time
        }
    }
}