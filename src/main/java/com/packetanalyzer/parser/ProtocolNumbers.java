package com.packetanalyzer.parser;

/** IP protocol numbers. {@code PacketAnalyzer::Protocol}. */
public final class ProtocolNumbers {
    public static final int ICMP = 1;
    public static final int TCP = 6;
    public static final int UDP = 17;

    private ProtocolNumbers() {
    }

    public static String toName(int protocol) {
        return switch (protocol) {
            case ICMP -> "ICMP";
            case TCP -> "TCP";
            case UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }
}
