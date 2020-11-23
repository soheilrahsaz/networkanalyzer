package com.network.analyzer.network.analyzer;

import com.network.analyzer.network.entity.PacketModel;
import com.network.analyzer.network.socket.UiModule;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;

public class NetworkAnalyzer implements PacketListener {
    private final int PACKET_COUNT = -1;

    private final PcapHandle analyzeHandler;
    private final UiModule uiModule;
    private final ArrayList<RecordedPacket> recordedPackets;
    private long idBase;

    public NetworkAnalyzer(PcapNetworkInterface networkInterface) throws PcapNativeException {
        int SNAP_LEN = 64 * 1024;
        int TIME_OUT = 10;
        analyzeHandler = networkInterface.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIME_OUT);
        uiModule = UiModule.getINSTANCE();
        recordedPackets = new ArrayList<>();
        idBase = 1;
    }

    public void start() throws PcapNativeException, InterruptedException, NotOpenException {
        if (!analyzeHandler.isOpen()) {
            throw new RuntimeException("this analyzer has been closed. create another instance.");
        }
        analyzeHandler.loop(PACKET_COUNT, this);
    }

    public void stop() throws PcapNativeException, InterruptedException, NotOpenException {
        if (analyzeHandler.isOpen()) {
            analyzeHandler.dispatch(PACKET_COUNT, this);
            analyzeHandler.breakLoop();
        }
        analyzeHandler.close();
        recordedPackets.clear();
        idBase = 1;
    }

    @Override
    public void gotPacket(Packet packet) {
        if (packet == null) {
            return;
        }
        PacketModel packetModel = AnalyzerUtils.convert(packet, idBase++);
        if (packetModel != null) {
            recordedPackets.add(new RecordedPacket(packetModel.id, packet));
            uiModule.sendRecord(packetModel);
        } else {
            recordedPackets.add(new RecordedPacket(null, packet));
        }
    }

    static class RecordedPacket {
        public Packet packet;
        public Long id;

        public RecordedPacket(Long id, Packet packet) {
            this.id = id;
            this.packet = packet;
        }
    }
}
