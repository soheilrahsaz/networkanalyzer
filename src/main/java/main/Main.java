package main;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import socket.UiModule;

public class Main {
    public static void main(String[] args) {
        UiModule uiModule = UiModule.getINSTANCE();
        try {
            PcapNetworkInterface networkInterface = Pcaps.findAllDevs().get(0);
            uiModule.startAnalyze(networkInterface.getName());
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
    }
}
