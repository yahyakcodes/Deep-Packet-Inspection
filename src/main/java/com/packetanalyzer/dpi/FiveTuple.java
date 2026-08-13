package com.packetanalyzer.dpi;

import com.packetanalyzer.parser.ProtocolNumbers;
import com.packetanalyzer.util.IpAddress;

/**
 * Uniquely identifies a connection/flow: source/destination IP, source/
 * destination port, and protocol. Direct port of {@code DPI::FiveTuple}
 * plus {@code DPI::FiveTupleHash} (types.h).
 *
 * <p>IP addresses use the packed representation described in
 * {@link IpAddress} - the same one the original C++ code uses internally.
 */
public final class FiveTuple {

    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int getSrcIp() {
        return srcIp;
    }

    public int getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    /** Same shape as the reverse tuple in the C++ version (unused by the current pipeline, kept for parity). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FiveTuple other)) {
            return false;
        }
        return srcIp == other.srcIp && dstIp == other.dstIp
                && srcPort == other.srcPort && dstPort == other.dstPort
                && protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        // Same boost::hash_combine-style mix as DPI::FiveTupleHash, so flow
        // routing to load-balancer/fast-path threads follows the same
        // distribution pattern as the original.
        long h = 0;
        h ^= (Integer.hashCode(srcIp) & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= (Integer.hashCode(dstIp) & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= (Integer.hashCode(srcPort) & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= (Integer.hashCode(dstPort) & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= (Integer.hashCode(protocol) & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int) (h ^ (h >>> 32));
    }

    @Override
    public String toString() {
        String proto = protocol == ProtocolNumbers.TCP ? "TCP" : protocol == ProtocolNumbers.UDP ? "UDP" : "?";
        return IpAddress.toDottedQuad(srcIp) + ":" + srcPort
                + " -> " + IpAddress.toDottedQuad(dstIp) + ":" + dstPort
                + " (" + proto + ")";
    }
}
