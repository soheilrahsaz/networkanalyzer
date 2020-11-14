package entity

data class PacketModel(
        val id: Long,
        val date: Long,
        val size: Int,
        val protocol: String,
        val srcMac: String,
        val srcIp: String,
        val srcPort: PortModel?,
        val dstMac: String,
        val dstIp: String,
        val dstPort: PortModel?,
        val extraInfo: String,
        val descriptor: String
)