package entity;

public class PacketModel {
    public long id;
    public long date;
    public int size;
    public String protocol;
    public String srcMac;
    public String srcIp;
    public PortModel srcPort;
    public String dstMac;
    public String dstIp;
    public PortModel dstPort;
    public String extraInfo;
    public String descriptor;

    public PacketModel(long id,
                       long date,
                       int size,
                       String protocol,
                       String srcMac,
                       String srcIp,
                       PortModel srcPort,
                       String dstMac,
                       String dstIp,
                       PortModel dstPort,
                       String extraInfo,
                       String descriptor
    ) {
        this.id = id;
        this.date = date;
        this.size = size;
        this.protocol = protocol;
        this.srcMac = srcMac;
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.dstMac = dstMac;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.extraInfo = extraInfo;
        this.descriptor = descriptor;
    }
}
