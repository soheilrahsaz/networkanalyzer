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
                                val tcp = ethernetPacket.get(TcpPacket::class.java)
                                tcp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = tcp.payload.toString()
                            }
                            IpNumber.UDP -> {
                                val udp = ethernetPacket.get(UdpPacket::class.java)
                                udp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = udp.payload.toString()
                            }
                            IpNumber.ICMPV4 -> {
                                val icmp = ethernetPacket.get(IcmpV4CommonPacket::class.java)
                                srcPort = null
                                dstPort = null
                                extInfo = "type: ${icmp.header.type} / code: ${icmp.header.code}\n${icmp.payload}"
                            }
                            IpNumber.IGMP -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ethernetPacket.payload.toString()
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ethernetPacket.payload.toString()
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
                                val tcp = ethernetPacket.get(TcpPacket::class.java)
                                tcp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = tcp.payload.toString()
                            }
                            IpNumber.UDP -> {
                                val udp = ethernetPacket.get(UdpPacket::class.java)
                                udp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = udp.payload.toString()
                            }
                            IpNumber.ICMPV6 -> {
                                val icmp = ethernetPacket.get(IcmpV6CommonPacket::class.java)
                                srcPort = null
                                dstPort = null
                                extInfo = "type: ${icmp.header.type} / code: ${icmp.header.code}\n${icmp.payload}"
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ethernetPacket.payload.toString()
                            }
                        }
                    }
                    EtherType.ARP -> {
                        protocol = EtherType.ARP.name()
                        val arp = ethernetPacket.get(ArpPacket::class.java)
                        srcIp = arp.header.srcProtocolAddr.hostAddress
                        dstIp = arp.header.dstProtocolAddr.hostAddress
                        srcPort = null
                        dstPort = null
                        extInfo = "operation: ${arp.header.operation.name()}\n${arp.payload}"
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
                        protocol = ethernetPacket.header.type.name()
                        srcIp = ""
                        dstIp = ""
                        srcPort = null
                        dstPort = null
                        extInfo = ethernetPacket.toString()
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