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
                var srcMac = ethernetPacket.header.srcAddr.toString()
                var dstMac = ethernetPacket.header.dstAddr.toString()

                val protocol: String
                val srcIp: String
                val dstIp: String

                val srcPort: PortModel?
                val dstPort: PortModel?
                val extInfo: String

                when (ethernetPacket.header.type) {
                    EtherType.IPV4 -> {
                        val ipv4 = ethernetPacket.payload.get(IpV4Packet::class.java)
                        ipv4.header.also {
                            protocol = it.protocol.name()
                            srcIp = it.srcAddr.hostAddress
                            dstIp = it.dstAddr.hostAddress
                        }
                        when (ipv4.header.protocol) {
                            IpNumber.TCP -> {
                                val tcp = ipv4.payload.get(TcpPacket::class.java)
                                tcp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = tcp.payload.toString()
                            }
                            IpNumber.UDP -> {
                                val udp = ipv4.payload.get(UdpPacket::class.java)
                                udp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = udp.payload.toString()
                            }
                            IpNumber.ICMPV4 -> {
                                val icmp = ipv4.payload.get(IcmpV4CommonPacket::class.java)
                                srcPort = null
                                dstPort = null
                                extInfo = "type: ${icmp.header.type} / code: ${icmp.header.code}\n${icmp.payload}"
                            }
                            IpNumber.IGMP -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ipv4.payload.toString()
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ipv4.payload.toString()
                            }
                        }
                    }
                    EtherType.IPV6 -> {
                        val ipv6 = ethernetPacket.payload.get(IpV6Packet::class.java)
                        ipv6.header.also {
                            protocol = it.protocol.name()
                            srcIp = it.srcAddr.hostAddress
                            dstIp = it.dstAddr.hostAddress
                        }
                        when (ipv6.header.protocol) {
                            IpNumber.TCP -> {
                                val tcp = ipv6.payload.get(TcpPacket::class.java)
                                tcp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = tcp.payload.toString()
                            }
                            IpNumber.UDP -> {
                                val udp = ipv6.payload.get(UdpPacket::class.java)
                                udp.header.also {
                                    srcPort = PortModel(it.srcPort.valueAsInt(), it.srcPort.name())
                                    dstPort = PortModel(it.dstPort.valueAsInt(), it.dstPort.name())
                                }
                                extInfo = udp.payload.toString()
                            }
                            IpNumber.ICMPV6 -> {
                                val icmp = ipv6.payload.get(IcmpV6CommonPacket::class.java)
                                srcPort = null
                                dstPort = null
                                extInfo = "type: ${icmp.header.type} / code: ${icmp.header.code}\n${icmp.payload}"
                            }
                            else -> {
                                srcPort = null
                                dstPort = null
                                extInfo = ipv6.payload.toString()
                            }
                        }
                    }
                    EtherType.ARP -> {
                        protocol = EtherType.ARP.name()
                        val arp = ethernetPacket.payload.get(ArpPacket::class.java)
                        arp.header.also {
                            srcIp = it.srcProtocolAddr.hostAddress
                            srcMac = it.srcHardwareAddr.toString()
                            dstIp = it.dstProtocolAddr.hostAddress
                            dstMac = it.dstHardwareAddr.toString()
                        }
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