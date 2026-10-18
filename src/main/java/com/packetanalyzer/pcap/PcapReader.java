package com.packetanalyzer.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

/**
 * Reads packets out of a .pcap file.
 *
 * <p>{@code PacketAnalyzer::PcapReader}
 * There is no dependency on libpcap/Npcap here: the project never
 * performs live capture, it only parses the well-documented, self
 * describing .pcap file format by hand, so this port does the same with
 * plain Java I/O. This is why the project does not pull in a library such
 * as Pcap4J - see the README for the reasoning.
 */
public final class PcapReader implements Closeable {

    private InputStream in;
    private PcapGlobalHeader globalHeader;
    private boolean open = false;

    /**
     * Opens a pcap file for reading and parses its 24-byte global header.
     *
     * @return {@code true} on success, {@code false} if the file could not
     *         be opened or does not look like a valid pcap file (mirrors
     *         the boolean-returning {@code PcapReader::open} in the original).
     */
    public boolean open(String filename) {
        close();
        try {
            in = new BufferedInputStream(new FileInputStream(filename));
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }

        byte[] headerBytes = new byte[PcapGlobalHeader.SIZE_BYTES];
        try {
            readFully(headerBytes);
        } catch (IOException e) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }

        // Determine byte order from the magic number, trying little-endian
        // first since that's what every modern capture host (x86/ARM) writes.
        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);
        int magic = buf.getInt(0);
        ByteOrder order;
        if (magic == PcapGlobalHeader.MAGIC_NATIVE) {
            order = ByteOrder.LITTLE_ENDIAN;
        } else {
            buf.order(ByteOrder.BIG_ENDIAN);
            magic = buf.getInt(0);
            if (magic == PcapGlobalHeader.MAGIC_NATIVE) {
                order = ByteOrder.BIG_ENDIAN;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%x%n", magic & 0xFFFFFFFFL);
                close();
                return false;
            }
        }

        buf.order(order);
        int versionMajor = buf.getShort(4) & 0xFFFF;
        int versionMinor = buf.getShort(6) & 0xFFFF;
        int thisZone = buf.getInt(8);
        int sigFigs = buf.getInt(12);
        long snapLen = buf.getInt(16) & 0xFFFFFFFFL;
        long network = buf.getInt(20) & 0xFFFFFFFFL;

        globalHeader = new PcapGlobalHeader(PcapGlobalHeader.MAGIC_NATIVE, versionMajor, versionMinor,
                thisZone, sigFigs, snapLen, network, order);
        open = true;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + versionMajor + "." + versionMinor);
        System.out.println("  Snaplen: " + snapLen + " bytes");
        System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));

        return true;
    }

    /** Reads the next packet, or empty if there are no more packets / on error. */
    public Optional<RawPacket> readNextPacket() {
        if (!open) {
            return Optional.empty();
        }

        byte[] headerBytes = new byte[PcapPacketHeader.SIZE_BYTES];
        try {
            readFully(headerBytes);
        } catch (IOException e) {
            // End of file (or a short read) - same as C++ !file_.good().
            return Optional.empty();
        }

        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(globalHeader.getByteOrder());
        long tsSec = buf.getInt(0) & 0xFFFFFFFFL;
        long tsUsec = buf.getInt(4) & 0xFFFFFFFFL;
        long inclLen = buf.getInt(8) & 0xFFFFFFFFL;
        long origLen = buf.getInt(12) & 0xFFFFFFFFL;

        if (inclLen > globalHeader.getSnapLen() || inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + inclLen);
            return Optional.empty();
        }

        byte[] data = new byte[(int) inclLen];
        try {
            readFully(data);
        } catch (IOException e) {
            System.err.println("Error: Could not read packet data");
            return Optional.empty();
        }

        PcapPacketHeader header = new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen);
        return Optional.of(new RawPacket(header, data));
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return open;
    }

    @Override
    public void close() {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // Nothing sensible to do; mirrors the C++ destructor, which
                // never surfaces close() failures either.
            }
            in = null;
        }
        open = false;
    }

    private void readFully(byte[] dest) throws IOException {
        int total = 0;
        while (total < dest.length) {
            int read = in.read(dest, total, dest.length - total);
            if (read < 0) {
                throw new IOException("Unexpected end of stream");
            }
            total += read;
        }
    }
}
