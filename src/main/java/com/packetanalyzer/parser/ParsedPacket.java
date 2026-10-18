package com.packetanalyzer.parser;

/**
 * Human-readable, parsed view of a raw packet's protocol headers.
 * {@code PacketAnalyzer::ParsedPacket}.
 * <p>This is a plain mutable holder filled in by {@link PacketParser#parse},
 * the same way filled in field-by-field.
 */
public final class ParsedPacket {

    // Timestamps
    private long timestampSec;
    private long timestampUsec;

    // Ethernet layer
    private String srcMac = "";
    private String destMac = "";
    private int etherType;

    // IP layer
    private boolean hasIp = false;
    private int ipVersion;
    private String srcIp = "";
    private String destIp = "";
    private int protocol; // TCP=6, UDP=17, ICMP=1
    private int ttl;

    // Transport layer
    private boolean hasTcp = false;
    private boolean hasUdp = false;
    private int srcPort;
    private int destPort;

    // TCP-specific
    private int tcpFlags;
    private long seqNumber;
    private long ackNumber;

    // Payload (offset/length into the owning RawPacket's data array;
    // there is no zero-copy pointer equivalent in Java, so callers that
    // need the bytes slice the original array using these two fields)
    private int payloadOffset;
    private int payloadLength;

    public long getTimestampSec() {
        return timestampSec;
    }

    public void setTimestampSec(long timestampSec) {
        this.timestampSec = timestampSec;
    }

    public long getTimestampUsec() {
        return timestampUsec;
    }

    public void setTimestampUsec(long timestampUsec) {
        this.timestampUsec = timestampUsec;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public String getDestMac() {
        return destMac;
    }

    public void setDestMac(String destMac) {
        this.destMac = destMac;
    }

    public int getEtherType() {
        return etherType;
    }

    public void setEtherType(int etherType) {
        this.etherType = etherType;
    }

    public boolean hasIp() {
        return hasIp;
    }

    public void setHasIp(boolean hasIp) {
        this.hasIp = hasIp;
    }

    public int getIpVersion() {
        return ipVersion;
    }

    public void setIpVersion(int ipVersion) {
        this.ipVersion = ipVersion;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDestIp() {
        return destIp;
    }

    public void setDestIp(String destIp) {
        this.destIp = destIp;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public boolean hasTcp() {
        return hasTcp;
    }

    public void setHasTcp(boolean hasTcp) {
        this.hasTcp = hasTcp;
    }

    public boolean hasUdp() {
        return hasUdp;
    }

    public void setHasUdp(boolean hasUdp) {
        this.hasUdp = hasUdp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    public int getTcpFlags() {
        return tcpFlags;
    }

    public void setTcpFlags(int tcpFlags) {
        this.tcpFlags = tcpFlags;
    }

    public long getSeqNumber() {
        return seqNumber;
    }

    public void setSeqNumber(long seqNumber) {
        this.seqNumber = seqNumber;
    }

    public long getAckNumber() {
        return ackNumber;
    }

    public void setAckNumber(long ackNumber) {
        this.ackNumber = ackNumber;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public void setPayloadOffset(int payloadOffset) {
        this.payloadOffset = payloadOffset;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
        this.payloadLength = payloadLength;
    }
}
