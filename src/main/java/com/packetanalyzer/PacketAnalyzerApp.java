package com.packetanalyzer;

import com.packetanalyzer.parser.EtherType;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.parser.ProtocolNumbers;
import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.RawPacket;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

/**
 * Basic packet-by-packet dumper: opens a pcap file and prints a
 * Wireshark-style breakdown of each packet's headers.
 * <p>
 * {@code packet_analyzer} target actually builds in the original project
 * As distinct from the more advanced multi-threaded {@code dpi_engine}
 * tool.
 * <pre>Usage: packet-analyzer &lt;pcap_file&gt; [max_packets]</pre>
 */
public final class PacketAnalyzerApp {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private PacketAnalyzerApp() {
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================");
        System.out.println();

        if (args.length < 1) {
            printUsage("packet-analyzer");
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = -1;
        if (args.length >= 2) {
            maxPackets = Integer.parseInt(args[1]);
        }

        PcapReader reader = new PcapReader();
        if (!reader.open(filename)) {
            System.exit(1);
        }

        System.out.println();
        System.out.println("--- Reading packets ---");

        int packetCount = 0;
        int parseErrors = 0;
        Optional<RawPacket> next;
        while ((next = reader.readNextPacket()).isPresent()) {
            packetCount++;
            RawPacket raw = next.get();
            ParsedPacket parsed = new ParsedPacket();

            if (PacketParser.parse(raw, parsed)) {
                printPacketSummary(raw, parsed, packetCount);
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }

            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println();
                System.out.println("(Stopped after " + maxPackets + " packets)");
                break;
            }
        }

        System.out.println();
        System.out.println("====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");

        reader.close();
    }

    private static void printPacketSummary(RawPacket raw, ParsedPacket pkt, int packetNum) {
        String timestamp = TIMESTAMP_FORMAT.format(Instant.ofEpochSecond(pkt.getTimestampSec()));

        System.out.println();
        System.out.println("========== Packet #" + packetNum + " ==========");
        System.out.printf("Time: %s.%06d%n", timestamp, pkt.getTimestampUsec());

        System.out.println();
        System.out.println("[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.getSrcMac());
        System.out.println("  Destination MAC: " + pkt.getDestMac());
        System.out.printf("  EtherType:       0x%04x", pkt.getEtherType());
        if (pkt.getEtherType() == EtherType.IPV4) {
            System.out.print(" (IPv4)");
        } else if (pkt.getEtherType() == EtherType.IPV6) {
            System.out.print(" (IPv6)");
        } else if (pkt.getEtherType() == EtherType.ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();

        if (pkt.hasIp()) {
            System.out.println();
            System.out.println("[IPv" + pkt.getIpVersion() + "]");
            System.out.println("  Source IP:      " + pkt.getSrcIp());
            System.out.println("  Destination IP: " + pkt.getDestIp());
            System.out.println("  Protocol:       " + ProtocolNumbers.toName(pkt.getProtocol()));
            System.out.println("  TTL:            " + pkt.getTtl());
        }

        if (pkt.hasTcp()) {
            System.out.println();
            System.out.println("[TCP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
            System.out.println("  Sequence Number:  " + pkt.getSeqNumber());
            System.out.println("  Ack Number:       " + pkt.getAckNumber());
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.getTcpFlags()));
        }

        if (pkt.hasUdp()) {
            System.out.println();
            System.out.println("[UDP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
        }

        if (pkt.getPayloadLength() > 0) {
            System.out.println();
            System.out.println("[Payload]");
            System.out.println("  Length: " + pkt.getPayloadLength() + " bytes");
            System.out.print("  Preview: ");
            byte[] data = raw.getData();
            int previewLen = Math.min(pkt.getPayloadLength(), 32);
            StringBuilder preview = new StringBuilder();
            for (int i = 0; i < previewLen; i++) {
                preview.append(String.format("%02x ", data[pkt.getPayloadOffset() + i] & 0xFF));
            }
            if (pkt.getPayloadLength() > 32) {
                preview.append("...");
            }
            System.out.println(preview.toString());
        }
    }

    private static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " <pcap_file> [max_packets]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  " + programName + " capture.pcap");
        System.out.println("  " + programName + " capture.pcap 10");
    }
}
