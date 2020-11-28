package com.network.analyzer.network.analyzer;

import com.network.analyzer.network.entity.PacketModel;
import com.network.analyzer.network.socket.UiModule;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.LinkLayerAddress;

import java.util.ArrayList;

public class NetworkAnalyzer implements PacketListener {
    private final int PACKET_COUNT = -1;

    private final PcapHandle analyzeHandler;
    private final UiModule uiModule;
    private long idBase;
    private final String interfaceMacAddress;

    public NetworkAnalyzer(PcapNetworkInterface networkInterface) throws PcapNativeException {
        int SNAP_LEN = 64 * 1024;
        int TIME_OUT = 10;
        ArrayList<LinkLayerAddress> linkLayerAddresses = networkInterface.getLinkLayerAddresses();
        if (!linkLayerAddresses.isEmpty()) {
            interfaceMacAddress = linkLayerAddresses.get(0).toString().toLowerCase();
        } else {
            interfaceMacAddress = "";
        }
        analyzeHandler = networkInterface.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIME_OUT);
        uiModule = UiModule.getINSTANCE();
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
        idBase = 1;
    }

    @Override
    public void gotPacket(Packet packet) {
        if (packet == null) {
            return;
        }
        PacketModel packetModel = AnalyzerUtils.convert(packet, idBase++, interfaceMacAddress);
        if (packetModel != null) {
            uiModule.sendRecord(packetModel);
        }
    }
}
