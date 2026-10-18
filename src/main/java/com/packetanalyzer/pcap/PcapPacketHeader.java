package com.packetanalyzer.pcap;

/**
 * The 16-byte per-packet header that precedes every packet's bytes in a
 * .pcap file. {@code PacketAnalyzer::PcapPacketHeader}.
 */
public final class PcapPacketHeader {

    public static final int SIZE_BYTES = 16;

    private final long tsSec;
    private final long tsUsec;
    private final long inclLen;
    private final long origLen;

    public PcapPacketHeader(long tsSec, long tsUsec, long inclLen, long origLen) {
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
    }

    /** Capture timestamp, seconds component. */
    public long getTsSec() {
        return tsSec;
    }

    /** Capture timestamp, microseconds component. */
    public long getTsUsec() {
        return tsUsec;
    }

    /** Number of bytes of this packet actually saved in the file. */
    public long getInclLen() {
        return inclLen;
    }

    /** Original on-the-wire length of the packet (may exceed inclLen if truncated). */
    public long getOrigLen() {
        return origLen;
    }
}
