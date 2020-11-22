package com.network.analyzer.network.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PacketModel {
    public long id;
    public long date;
    public int size;
    public String protocol;
    public String srcMac;
    public int ipVersion;
    public String srcIp;
    public PortModel srcPort;
    public String dstMac;
    public String dstIp;
    public PortModel dstPort;
    public String extraInfo;
    public String descriptor;
}
