package com.packetanalyzer.pcap;

/**
 * A single captured packet exactly as read from a .pcap file: its header
 * plus the raw bytes. Direct port of {@code PacketAnalyzer::RawPacket}.
 */
public final class RawPacket {

    private final PcapPacketHeader header;
    private final byte[] data;

    public RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }

    public PcapPacketHeader getHeader() {
        return header;
    }

    /** The raw captured bytes, starting with the Ethernet header. */
    public byte[] getData() {
        return data;
    }
}
