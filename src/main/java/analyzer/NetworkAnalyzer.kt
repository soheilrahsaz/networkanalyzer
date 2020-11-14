package analyzer

import analyzer.AnalyzerUtils.Companion.convert
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.packet.Packet
import socket.UiModule
import java.lang.RuntimeException

class NetworkAnalyzer(networkInterface: PcapNetworkInterface) : PacketListener {

    companion object {
        private const val SNAP_LEN = 64 * 1024
        private const val TIME_OUT = 10
        private const val PACKET_COUNT = -1
    }

    private val analyzeHandler: PcapHandle
    private val uiModule: UiModule
    private val recordedPackets: ArrayList<Pair<Long?, Packet>>
    private var idBase: Long

    init {
        analyzeHandler = networkInterface.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIME_OUT)
        uiModule = UiModule.getINSTANCE()
        recordedPackets = ArrayList()
        idBase = 0L
    }

    fun start() {
        if (!analyzeHandler.isOpen) {
            throw RuntimeException("this analyzer has been closed. create another instance.")
        }
        analyzeHandler.loop(PACKET_COUNT, this)
    }

    fun stop() {
        if (analyzeHandler.isOpen) {
            analyzeHandler.dispatch(PACKET_COUNT, this)
            analyzeHandler.breakLoop()
        }
        analyzeHandler.close()
        recordedPackets.clear()
        idBase = 0L
    }


    override fun gotPacket(packet: Packet?) {
        packet ?: return
        packet.convert(idBase++)?.let {
            recordedPackets.add(Pair(it.id, packet))
            uiModule.sendRecord(it)
        } ?: run {
            recordedPackets.add(Pair(null, packet))
        }
    }
}