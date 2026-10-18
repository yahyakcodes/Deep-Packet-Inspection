package com.packetanalyzer.parser;

/** EtherType values. {@code PacketAnalyzer::EtherType} namespace. */
public final class EtherType {
    public static final int IPV4 = 0x0800;
    public static final int IPV6 = 0x86DD;
    public static final int ARP = 0x0806;

    private EtherType() {
    }
}
