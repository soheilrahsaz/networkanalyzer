package com.network.analyzer.controller;

import com.network.analyzer.domain.ChatMessage;
import com.network.analyzer.network.entity.PacketModel;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;

@Controller
public class WebSocketController {

    private final SimpMessagingTemplate template;

    public WebSocketController(SimpMessagingTemplate template) {
        this.template = template;
    }

//    @MessageMapping("/network")
//    @SendTo("/network/packet")
//    public ChatMessage greeting(ChatMessage message) throws Exception {
//        return new ChatMessage("Server", RandomStringUtils.randomAlphanumeric(10));
//    }
//
//    @Scheduled(fixedRate = 500)
//    public void test()
//    {
//        template.convertAndSend("/network/packet", new ChatMessage("Ser ver", RandomStringUtils.randomAlphanumeric(10)));
//    }


    public void sendPacket(PacketModel packetModel)
    {
        template.convertAndSend("/network/packet", packetModel);
    }
}
