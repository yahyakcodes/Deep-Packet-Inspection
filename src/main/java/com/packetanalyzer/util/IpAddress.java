package com.packetanalyzer.util;

/**
 * Helper for converting between dotted-quad IPv4 strings and the packed
 * 32-bit representation used throughout the engine.
 *
 * <p>Port note: the original C++ code does not call {@code ntohl()} on IPv4
 * addresses. {@code packet_parser.cpp} copies the 4 raw address bytes
 * straight into a {@code uint32_t} with {@code memcpy}, and
 * {@code PacketParser::ipToString()} / the {@code parseIP()} lambdas in
 * {@code dpi_mt.cpp} both read that integer back out one byte at a time
 * starting from the least-significant byte. The result is a "packed"
 * integer where the first dotted-quad octet lives in bits 0-7, the second
 * in bits 8-15, and so on - NOT true network byte order. It is internally
 * consistent (parsing and formatting always agree, and IP-based blocking
 * matches correctly) so this class reproduces the exact same packing
 * scheme rather than "fixing" it to a textbook big-endian conversion,
 * to keep flow hashing, IP display, and {@code --block-ip} behavior
 * identical to the original binary.
 */
public final class IpAddress {

    private IpAddress() {
    }

    /** Packs 4 octets (each 0-255) into the engine's internal representation. */
    public static int packOctets(int o0, int o1, int o2, int o3) {
        return (o0 & 0xFF) | ((o1 & 0xFF) << 8) | ((o2 & 0xFF) << 16) | ((o3 & 0xFF) << 24);
    }

    /**
     * Parses a dotted-quad string ("192.168.1.50") into the packed
     * representation. Mirrors the small hand-rolled parser used for
     * {@code --block-ip} and five-tuple construction in the original
     * {@code dpi_mt.cpp} (non-numeric characters other than '.' are
     * ignored, exactly like the original).
     */
    public static int parseDottedQuad(String ip) {
        int result = 0;
        int octet = 0;
        int shift = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }

    /** Formats the packed representation back into dotted-quad notation. */
    public static String toDottedQuad(int packedIp) {
        return ((packedIp) & 0xFF) + "."
                + ((packedIp >>> 8) & 0xFF) + "."
                + ((packedIp >>> 16) & 0xFF) + "."
                + ((packedIp >>> 24) & 0xFF);
    }
}
