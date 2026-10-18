package com.packetanalyzer.dpi;

/**
 * A fully self-contained packet as it travels between the reader,
 * load-balancer, and fast-path threads. {@code Packet}
 * Defined locally in dpi_mt.java.
 */
public final class PacketJob {

    private final long id;
    private final long tsSec;
    private final long tsUsec;
    private final FiveTuple tuple;
    private final byte[] data;
    private final int tcpFlags;
    private final int payloadOffset;
    private final int payloadLength;

    public PacketJob(long id, long tsSec, long tsUsec, FiveTuple tuple, byte[] data,
                      int tcpFlags, int payloadOffset, int payloadLength) {
        this.id = id;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.tuple = tuple;
        this.data = data;
        this.tcpFlags = tcpFlags;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
    }

    public long getId() {
        return id;
    }

    public long getTsSec() {
        return tsSec;
    }

    public long getTsUsec() {
        return tsUsec;
    }

    public FiveTuple getTuple() {
        return tuple;
    }

    public byte[] getData() {
        return data;
    }

    public int getTcpFlags() {
        return tcpFlags;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public int getPayloadLength() {
        return payloadLength;
    }
}
