package com.packetanalyzer.parser;

/** TCP header flag bits. {@code PacketAnalyzer::TCPFlags}. */
public final class TcpFlags {
    public static final int FIN = 0x01;
    public static final int SYN = 0x02;
    public static final int RST = 0x04;
    public static final int PSH = 0x08;
    public static final int ACK = 0x10;
    public static final int URG = 0x20;

    private TcpFlags() {
    }

    /** Human-readable space-separated flag list, e.g. "SYN ACK", or "none". */
    public static String toDisplayString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & SYN) != 0) {
            sb.append("SYN ");
        }
        if ((flags & ACK) != 0) {
            sb.append("ACK ");
        }
        if ((flags & FIN) != 0) {
            sb.append("FIN ");
        }
        if ((flags & RST) != 0) {
            sb.append("RST ");
        }
        if ((flags & PSH) != 0) {
            sb.append("PSH ");
        }
        if ((flags & URG) != 0) {
            sb.append("URG ");
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.length() == 0 ? "none" : sb.toString();
    }
}
