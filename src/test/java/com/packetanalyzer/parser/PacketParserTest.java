package com.packetanalyzer.parser;

import com.packetanalyzer.pcap.PcapPacketHeader;
import com.packetanalyzer.pcap.RawPacket;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PacketParserTest {

    private static byte[] buildEthernetIpv4TcpPacket() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Ethernet header: dest MAC, src MAC, EtherType = IPv4
        out.writeBytes(new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}); // dest
        out.writeBytes(new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, 0x00, 0x00, 0x01}); // src
        writeU16(out, EtherType.IPV4);

        byte[] payload = "hello".getBytes(StandardCharsets.US_ASCII);
        int tcpHeaderLen = 20;
        int ipHeaderLen = 20;
        int ipTotalLen = ipHeaderLen + tcpHeaderLen + payload.length;

        // IPv4 header
        out.write(0x45); // version=4, IHL=5 (20 bytes)
        out.write(0x00); // DSCP/ECN
        writeU16(out, ipTotalLen);
        writeU16(out, 0x1234); // identification
        writeU16(out, 0x0000); // flags/fragment offset
        out.write(64); // TTL
        out.write(ProtocolNumbers.TCP);
        writeU16(out, 0x0000); // header checksum (unchecked by parser)
        out.writeBytes(new byte[]{(byte) 192, (byte) 168, 1, 100}); // src IP
        out.writeBytes(new byte[]{8, 8, 8, 8}); // dest IP

        // TCP header
        writeU16(out, 54321); // src port
        writeU16(out, 443);   // dest port
        writeU32(out, 1000L); // seq number
        writeU32(out, 2000L); // ack number
        out.write((5 << 4)); // data offset = 5 (20 bytes), reserved bits = 0
        out.write(TcpFlags.SYN | TcpFlags.ACK);
        writeU16(out, 65535); // window
        writeU16(out, 0x0000); // checksum
        writeU16(out, 0x0000); // urgent pointer

        out.writeBytes(payload);

        return out.toByteArray();
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >> 24) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    @Test
    void parsesEthernetIpv4TcpPacket() {
        byte[] data = buildEthernetIpv4TcpPacket();
        RawPacket raw = new RawPacket(new PcapPacketHeader(1_700_000_000L, 123456L, data.length, data.length), data);
        ParsedPacket parsed = new ParsedPacket();

        assertTrue(PacketParser.parse(raw, parsed));
        assertTrue(parsed.hasIp());
        assertTrue(parsed.hasTcp());
        assertEquals("192.168.1.100", parsed.getSrcIp());
        assertEquals("8.8.8.8", parsed.getDestIp());
        assertEquals(ProtocolNumbers.TCP, parsed.getProtocol());
        assertEquals(54321, parsed.getSrcPort());
        assertEquals(443, parsed.getDestPort());
        assertEquals(1000L, parsed.getSeqNumber());
        assertEquals(2000L, parsed.getAckNumber());
        assertEquals(TcpFlags.SYN | TcpFlags.ACK, parsed.getTcpFlags());
        assertEquals(5, parsed.getPayloadLength());
        assertEquals("hello", new String(data, parsed.getPayloadOffset(), parsed.getPayloadLength(), StandardCharsets.US_ASCII));
    }
}
