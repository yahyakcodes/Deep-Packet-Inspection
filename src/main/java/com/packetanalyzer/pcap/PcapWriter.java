package com.packetanalyzer.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes an output .pcap file: a 24-byte global header followed by any
 * number of (16-byte header + payload) packet records.
 *
 * <p>The original {@code DPIEngine::process()} in dpi_mt.cpp writes the
 * global header it just read back out verbatim, and then always writes new
 * packet headers in the host's native byte order. Every platform the
 * original project targets (and this Java port) is little-endian, so this
 * writer always emits standard little-endian pcap files - the same format
 * Wireshark and tcpdump write by default.
 */
public final class PcapWriter implements Closeable {

    private final OutputStream out;

    public PcapWriter(String filename) throws IOException {
        this.out = new BufferedOutputStream(new FileOutputStream(filename));
    }

    public void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(PcapGlobalHeader.SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(PcapGlobalHeader.MAGIC_NATIVE);
        buf.putShort((short) header.getVersionMajor());
        buf.putShort((short) header.getVersionMinor());
        buf.putInt(header.getThisZone());
        buf.putInt(header.getSigFigs());
        buf.putInt((int) header.getSnapLen());
        buf.putInt((int) header.getNetwork());
        out.write(buf.array());
    }

    public void writePacket(long tsSec, long tsUsec, byte[] data) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(PcapPacketHeader.SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) tsSec);
        buf.putInt((int) tsUsec);
        buf.putInt(data.length);
        buf.putInt(data.length);
        out.write(buf.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
