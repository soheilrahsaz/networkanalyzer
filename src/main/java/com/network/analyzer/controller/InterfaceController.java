package com.network.analyzer.controller;

import com.network.analyzer.network.entity.InterfaceModel;
import com.network.analyzer.network.socket.UiModule;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/interface")
public class InterfaceController {

    private final WebSocketController webSocketController;

    private final UiModule uiModule = UiModule.getINSTANCE();

    public InterfaceController(WebSocketController webSocketController) {
        this.webSocketController = webSocketController;
    }

    @GetMapping
    public List<InterfaceModel> getInterfaces() throws Exception
    {
        return uiModule.getAllNetworkInterfacesName();
    }

    @PostMapping
    public Boolean startAnalyzing(@RequestBody InterfaceModel interfaceModel) throws Exception
    {
        uiModule.setWebSocketController(webSocketController);
        final String interfaceName = interfaceModel.getName();
        new Thread(() -> {
            try {
                uiModule.startAnalyze(interfaceName);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        return true;
    }
}
