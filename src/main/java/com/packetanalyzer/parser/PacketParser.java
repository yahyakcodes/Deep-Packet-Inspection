package com.packetanalyzer.parser;

import com.packetanalyzer.pcap.RawPacket;
import com.packetanalyzer.util.IpAddress;

/**
 * Parses the Ethernet/IPv4/TCP/UDP headers out of a raw captured packet.
 * Direct port of {@code PacketAnalyzer::PacketParser} (packet_parser.cpp).
 */
public final class PacketParser {

    private static final int ETH_HEADER_LEN = 14;
    private static final int MIN_IP_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {
    }

    /**
     * Parses a raw packet into a {@link ParsedPacket}.
     *
     * @return {@code true} if at least the Ethernet header parsed
     *         successfully (matches the original: IPv4/TCP/UDP parse
     *         failures below the Ethernet layer also return {@code false}).
     */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        byte[] data = raw.getData();
        int len = data.length;

        parsed.setTimestampSec(raw.getHeader().getTsSec());
        parsed.setTimestampUsec(raw.getHeader().getTsUsec());
        parsed.setHasIp(false);
        parsed.setHasTcp(false);
        parsed.setHasUdp(false);

        int[] offsetHolder = {0};
        if (!parseEthernet(data, len, parsed, offsetHolder)) {
            return false;
        }

        if (parsed.getEtherType() == EtherType.IPV4) {
            if (!parseIPv4(data, len, parsed, offsetHolder)) {
                return false;
            }
            if (parsed.getProtocol() == ProtocolNumbers.TCP) {
                if (!parseTcp(data, len, parsed, offsetHolder)) {
                    return false;
                }
            } else if (parsed.getProtocol() == ProtocolNumbers.UDP) {
                if (!parseUdp(data, len, parsed, offsetHolder)) {
                    return false;
                }
            }
        }

        int offset = offsetHolder[0];
        if (offset < len) {
            parsed.setPayloadOffset(offset);
            parsed.setPayloadLength(len - offset);
        } else {
            parsed.setPayloadOffset(offset);
            parsed.setPayloadLength(0);
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < ETH_HEADER_LEN) {
            return false;
        }
        parsed.setDestMac(macToString(data, 0));
        parsed.setSrcMac(macToString(data, 6));
        parsed.setEtherType(readUint16BE(data, 12));
        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offsetHolder) {
        int offset = offsetHolder[0];
        if (len < offset + MIN_IP_HEADER_LEN) {
            return false;
        }

        int versionIhl = data[offset] & 0xFF;
        int ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (ipVersion != 4) {
            return false;
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset + ipHeaderLen) {
            return false;
        }

        parsed.setIpVersion(ipVersion);
        parsed.setTtl(data[offset + 8] & 0xFF);
        parsed.setProtocol(data[offset + 9] & 0xFF);

        int srcIp = IpAddress.packOctets(data[offset + 12], data[offset + 13],
                data[offset + 14], data[offset + 15]);
        int destIp = IpAddress.packOctets(data[offset + 16], data[offset + 17],
                data[offset + 18], data[offset + 19]);
        parsed.setSrcIp(IpAddress.toDottedQuad(srcIp));
        parsed.setDestIp(IpAddress.toDottedQuad(destIp));

        parsed.setHasIp(true);
        offsetHolder[0] = offset + ipHeaderLen;
        return true;
    }

    private static boolean parseTcp(byte[] data, int len, ParsedPacket parsed, int[] offsetHolder) {
        int offset = offsetHolder[0];
        if (len < offset + MIN_TCP_HEADER_LEN) {
            return false;
        }

        parsed.setSrcPort(readUint16BE(data, offset));
        parsed.setDestPort(readUint16BE(data, offset + 2));
        parsed.setSeqNumber(readUint32BE(data, offset + 4));
        parsed.setAckNumber(readUint32BE(data, offset + 8));

        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        parsed.setTcpFlags(data[offset + 13] & 0xFF);

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset + tcpHeaderLen) {
            return false;
        }

        parsed.setHasTcp(true);
        offsetHolder[0] = offset + tcpHeaderLen;
        return true;
    }

    private static boolean parseUdp(byte[] data, int len, ParsedPacket parsed, int[] offsetHolder) {
        int offset = offsetHolder[0];
        if (len < offset + UDP_HEADER_LEN) {
            return false;
        }
        parsed.setSrcPort(readUint16BE(data, offset));
        parsed.setDestPort(readUint16BE(data, offset + 2));
        parsed.setHasUdp(true);
        offsetHolder[0] = offset + UDP_HEADER_LEN;
        return true;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String tcpFlagsToString(int flags) {
        return TcpFlags.toDisplayString(flags);
    }

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long readUint32BE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }
}
