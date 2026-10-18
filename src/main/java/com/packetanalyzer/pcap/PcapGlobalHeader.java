package com.packetanalyzer.pcap;

import java.nio.ByteOrder;

/**
 * The 24-byte global header at the start of every .pcap file.
 * {@code PacketAnalyzer::PcapGlobalHeader}
 */
public final class PcapGlobalHeader {

    public static final int SIZE_BYTES = 24;

    /** Native-endian magic number for a standard (microsecond-resolution) pcap file. */
    public static final int MAGIC_NATIVE = 0xa1b2c3d4;

    /** Same file, but written by a host with the opposite byte order. */
    public static final int MAGIC_SWAPPED = 0xd4c3b2a1;

    private final int magicNumber;
    private final int versionMajor;
    private final int versionMinor;
    private final int thisZone;
    private final int sigFigs;
    private final long snapLen;
    private final long network;
    private final ByteOrder byteOrder;

    public PcapGlobalHeader(int magicNumber, int versionMajor, int versionMinor,
                             int thisZone, int sigFigs, long snapLen, long network,
                             ByteOrder byteOrder) {
        this.magicNumber = magicNumber;
        this.versionMajor = versionMajor;
        this.versionMinor = versionMinor;
        this.thisZone = thisZone;
        this.sigFigs = sigFigs;
        this.snapLen = snapLen;
        this.network = network;
        this.byteOrder = byteOrder;
    }

    public int getMagicNumber() {
        return magicNumber;
    }

    public int getVersionMajor() {
        return versionMajor;
    }

    public int getVersionMinor() {
        return versionMinor;
    }

    public int getThisZone() {
        return thisZone;
    }

    public int getSigFigs() {
        return sigFigs;
    }

    /** Max length of captured packets, as an unsigned value. */
    public long getSnapLen() {
        return snapLen;
    }

    /** Data-link type; 1 = Ethernet. */
    public long getNetwork() {
        return network;
    }

    /** Byte order the source file was written in (needed only for reading). */
    public ByteOrder getByteOrder() {
        return byteOrder;
    }
}
