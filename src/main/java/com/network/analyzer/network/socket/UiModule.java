package com.network.analyzer.network.socket;

import com.network.analyzer.controller.WebSocketController;
import com.network.analyzer.network.analyzer.AnalyzerUtils;
import com.network.analyzer.network.analyzer.NetworkAnalyzer;
import com.network.analyzer.network.entity.InterfaceModel;
import com.network.analyzer.network.entity.PacketModel;
import lombok.Data;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

@Data
public class UiModule {
    private static UiModule INSTANCE;
    private NetworkAnalyzer analyzer;

    public static UiModule getINSTANCE() {
        if (INSTANCE == null) {
            INSTANCE = new UiModule();
        }
        return INSTANCE;
    }


    //Client methods
    public List<InterfaceModel> getAllNetworkInterfacesName() throws PcapNativeException {
        return AnalyzerUtils.getAllNetworkInterfacesName();
    }

    public void startAnalyze(String nifName) throws PcapNativeException, NotOpenException, InterruptedException {
        stopAnalyze();
        PcapNetworkInterface nif = Pcaps.getDevByName(nifName);
        analyzer = new NetworkAnalyzer(nif);
        analyzer.start();
    }

    public void stopAnalyze() throws PcapNativeException, InterruptedException, NotOpenException {
        if (analyzer != null) {
            analyzer.stop();
            analyzer = null;
        }
    }

    public void blockPacket(long packetId) {
        //TODO: Implement Bonus part of project
    }


    private WebSocketController WebSocketController;
    //Server methods
    public void sendRecord(PacketModel packetModel) {
        WebSocketController.sendPacket(packetModel);
    }
}
