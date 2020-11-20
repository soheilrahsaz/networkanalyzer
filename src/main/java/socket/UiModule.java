package socket;

import analyzer.AnalyzerUtils;
import analyzer.NetworkAnalyzer;
import com.google.gson.Gson;
import entity.InterfaceModel;
import entity.PacketModel;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

public class UiModule {
    private static UiModule INSTANCE;
    private NetworkAnalyzer analyzer;
    private final Gson gson;

    public static UiModule getINSTANCE() {
        if (INSTANCE == null) {
            INSTANCE = new UiModule();
        }
        return INSTANCE;
    }

    private UiModule() {
        gson = new Gson();
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

    //Server methods
    public void sendRecord(PacketModel packetModel) {
        String rawJson = gson.toJson(packetModel);
        System.out.println(rawJson);
        System.out.println("**********************");
    }
}
