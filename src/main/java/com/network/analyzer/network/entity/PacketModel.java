package com.network.analyzer.network.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PacketModel {
    public long id;
    public int type;
    public String date;
    public int size;
    public String protocol;
    public int ipVersion;
    public String srcMac;
    public String srcIp;
    public PortModel srcPort;
    public String dstMac;
    public String dstIp;
    public PortModel dstPort;
    public String extraInfo;
    public String descriptor;
}
