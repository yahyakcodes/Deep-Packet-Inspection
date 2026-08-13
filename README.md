# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Core Processing Steps)](#5-the-journey-of-a-packet-core-processing-steps)
6. [The Journey of a Packet (Multi-threaded Pipeline)](#6-the-journey-of-a-packet-multi-threaded-pipeline)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS                │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)    │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)        │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network) │
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

In this project, a flow is represented by the immutable `FiveTuple` class (`com.packetanalyzer.dpi.FiveTuple`), which overrides `equals()`/`hashCode()` so it can be used directly as a `HashMap` key.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Entry Points

| Tool | Class | Use Case |
|------|-------|----------|
| Packet Analyzer | `com.packetanalyzer.PacketAnalyzerApp` | Prints a Wireshark-style header breakdown for every packet - useful for learning packet structure or debugging a capture |
| DPI Engine | `com.packetanalyzer.dpi.DpiEngineApp` | Multi-threaded classification, blocking, and reporting - the production tool |

Both are plain Java `main()` classes with no native dependencies - `.pcap` files are parsed with hand-written binary I/O (`java.io`/`java.nio`), so there's no Npcap/WinPcap/libpcap driver to install.

---

## 4. File Structure

```
DeepPacketInspection/
├── pom.xml                          # Maven build configuration (Java 21)
├── README.md                        # This file!
└── src/
    ├── main/java/com/packetanalyzer/
    │   ├── PacketAnalyzerApp.java   # ★ Packet dumper entry point ★
    │   │
    │   ├── pcap/                    # PCAP file handling
    │   │   ├── PcapGlobalHeader.java
    │   │   ├── PcapPacketHeader.java
    │   │   ├── RawPacket.java
    │   │   ├── PcapReader.java
    │   │   └── PcapWriter.java
    │   │
    │   ├── parser/                  # Network protocol parsing
    │   │   ├── EtherType.java
    │   │   ├── ProtocolNumbers.java
    │   │   ├── TcpFlags.java
    │   │   ├── ParsedPacket.java
    │   │   └── PacketParser.java
    │   │
    │   ├── util/
    │   │   └── IpAddress.java       # Shared IPv4 packing/formatting helper
    │   │
    │   └── dpi/                     # Deep packet inspection & filtering
    │       ├── DpiEngineApp.java    # ★ DPI engine entry point ★
    │       ├── DpiEngine.java       # Orchestrator
    │       ├── LoadBalancer.java
    │       ├── FastPathProcessor.java
    │       ├── ThreadSafeQueue.java
    │       ├── SniExtractor.java
    │       ├── HttpHostExtractor.java
    │       ├── DnsExtractor.java
    │       ├── QuicSniExtractor.java
    │       ├── Rules.java
    │       ├── Statistics.java
    │       ├── AppType.java
    │       ├── FiveTuple.java
    │       ├── FlowEntry.java
    │       └── PacketJob.java
    │
    └── test/java/com/packetanalyzer/    # JUnit 5 tests
```

---

## 5. The Journey of a Packet (Core Processing Steps)

Let's trace a single packet through the DPI pipeline, step by step, ignoring threading for now (that's covered in Section 6). This is exactly what happens inside each Fast Path worker.

### Step 1: Read PCAP File

```java
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```java
Optional<RawPacket> next;
while ((next = reader.readNextPacket()).isPresent()) {
    RawPacket raw = next.get();
    // raw.getData() contains the packet bytes
    // raw.getHeader() contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = `inclLen`)
3. Return an empty `Optional` when there are no more packets

### Step 3: Parse Protocol Headers

```java
ParsedPacket parsed = new ParsedPacket();
PacketParser.parse(raw, parsed);
```

**What happens (inside `PacketParser`):**

```
raw.getData() bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.getSrcMac()    = "00:11:22:33:44:55"
parsed.getDestMac()   = "aa:bb:cc:dd:ee:ff"
parsed.getSrcIp()     = "192.168.1.100"
parsed.getDestIp()    = "172.217.14.206"
parsed.getSrcPort()   = 54321
parsed.getDestPort()  = 443
parsed.getProtocol()  = 6 (TCP)
parsed.hasTcp()       = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

> If all you need is this header breakdown printed to the console for every packet, that's exactly what `PacketAnalyzerApp` does - it stops here and never touches flows, SNI, or blocking.

### Step 4: Create Five-Tuple and Look Up Flow

```java
int srcIp = IpAddress.parseDottedQuad(parsed.getSrcIp());
int dstIp = IpAddress.parseDottedQuad(parsed.getDestIp());
FiveTuple tuple = new FiveTuple(srcIp, dstIp,
        parsed.getSrcPort(), parsed.getDestPort(), parsed.getProtocol());

FlowEntry flow = flows.computeIfAbsent(tuple, FlowEntry::new);
```

**What happens:**
- The flow table is a `HashMap<FiveTuple, FlowEntry>`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```java
// For HTTPS traffic (port 443)
if (tuple.getDstPort() == 443 && pkt.getPayloadLength() > 5) {
    Optional<String> sni = SniExtractor.extract(
            pkt.getData(), pkt.getPayloadOffset(), pkt.getPayloadLength());
    if (sni.isPresent()) {
        flow.setSni(sni.get());                    // "www.youtube.com"
        flow.setAppType(AppType.fromSni(sni.get())); // AppType.YOUTUBE
    }
}
```

**What happens (inside `SniExtractor`):**

1. **Check if it's a TLS Client Hello:**
```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
```

2. **Navigate to Extensions:**
```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
```

3. **Find SNI Extension (type 0x0000):**
```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
```

4. **Map SNI to App Type:**
```java
   // In AppType.fromSni()
   if (sni.contains("youtube")) {
       return AppType.YOUTUBE;
   }
```

### Step 6: Check Blocking Rules

```java
if (rules.isBlocked(tuple.getSrcIp(), flow.getAppType(), flow.getSni())) {
    flow.setBlocked(true);
}
```

**What happens (inside `Rules`):**
```java
// Check IP blacklist
if (blockedIps.contains(srcIp)) return true;

// Check app blacklist
if (blockedApps.contains(app)) return true;

// Check domain blacklist (substring match)
for (String domain : blockedDomains) {
    if (sni != null && sni.contains(domain)) return true;
}

return false;
```

### Step 7: Forward or Drop

```java
if (flow.isBlocked()) {
    stats.dropped.incrementAndGet();
    // Don't write to output
} else {
    stats.forwarded.incrementAndGet();
    outputQueue.push(pkt); // eventually written to the output pcap
}
```

### Step 8: Generate Report

After processing all packets:
```java
// Count apps (done incrementally as packets are processed)
stats.recordApp(flow.getAppType(), flow.getSni());

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Pipeline)

`DpiEngineApp` adds **parallelism** on top of the exact same core logic above, for high performance on large captures.

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % N       │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % N     │               │hash % N     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing (Steps 3-8 above)
3. **Consistent Hashing:** Same 5-tuple always goes to the same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):          hash → FP2
Packet 2 (SYN-ACK):      hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):         hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader (main thread of `DpiEngine.process()`)

```java
while ((next = reader.readNextPacket()).isPresent()) {
    PacketJob pkt = buildPacketJob(next.get());

    // Hash to select Load Balancer
    int lbIndex = Math.floorMod(pkt.getTuple().hashCode(), loadBalancers.size());

    // Push to LB's queue
    loadBalancers.get(lbIndex).getInputQueue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```java
// LoadBalancer.run()
while (running.get()) {
    Optional<PacketJob> maybePacket = inputQueue.pop(100);
    if (maybePacket.isEmpty()) continue;
    PacketJob pkt = maybePacket.get();

    // Hash to select Fast Path
    int fpIndex = Math.floorMod(pkt.getTuple().hashCode(), fastPaths.size());
    fastPaths.get(fpIndex).getInputQueue().push(pkt);
}
```

#### Step 3: Fast Path Thread

```java
// FastPathProcessor.run()
while (running.get()) {
    Optional<PacketJob> maybePacket = inputQueue.pop(100);
    if (maybePacket.isEmpty()) continue;
    PacketJob pkt = maybePacket.get();

    // Look up flow (each FP has its own flow table - no locking needed)
    FlowEntry flow = flows.computeIfAbsent(pkt.getTuple(), FlowEntry::new);

    // Classify (SNI/Host extraction)
    if (!flow.isClassified()) classifyFlow(pkt, flow);

    // Check rules
    if (!flow.isBlocked()) {
        flow.setBlocked(rules.isBlocked(pkt.getTuple().getSrcIp(), flow.getAppType(), flow.getSni()));
    }

    if (flow.isBlocked()) {
        stats.dropped.incrementAndGet();
    } else {
        outputQueue.push(pkt);
    }
}
```

#### Step 4: Output Writer Thread

```java
private void outputWriterLoop(PcapWriter writer, AtomicBoolean outputRunning) {
    while (outputRunning.get() || outputQueue.size() > 0) {
        Optional<PacketJob> maybePacket = outputQueue.pop(50);
        if (maybePacket.isEmpty()) continue;
        PacketJob pkt = maybePacket.get();
        writer.writePacket(pkt.getTsSec(), pkt.getTsUsec(), pkt.getData());
    }
}
```

### Thread-Safe Queue

The piece that makes multi-threading work: `ThreadSafeQueue<T>`, a bounded blocking queue built with a `ReentrantLock` and two `Condition`s (`notEmpty`, `notFull`):

```java
public void push(T item) {
    lock.lock();
    try {
        while (queue.size() >= maxSize && !shutdown) {
            notFull.awaitUninterruptibly();
        }
        if (shutdown) return;
        queue.addLast(item);
        notEmpty.signal();          // Wake up a waiting consumer
    } finally {
        lock.unlock();
    }
}

public Optional<T> pop(long timeoutMs) {
    lock.lock();
    try {
        long nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (queue.isEmpty() && !shutdown) {
            if (nanos <= 0L) return Optional.empty();
            nanos = notEmpty.awaitNanos(nanos);
        }
        if (queue.isEmpty()) return Optional.empty();
        T item = queue.removeFirst();
        notFull.signal();
        return Optional.of(item);
    } finally {
        lock.unlock();
    }
}
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers, blocks if full
- `pop(timeoutMs)`: Consumer waits up to `timeoutMs` for an item, then gives up (so threads can check their `running` flag periodically and shut down cleanly)
- `ReentrantLock`: Only one thread can access the queue's internals at a time
- `Condition.await*`: Efficient waiting (no busy-loop burning CPU)

---

## 7. Deep Dive: Each Component

### `pcap/PcapReader.java` / `pcap/PcapWriter.java`

**Purpose:** Read and write network captures compatible with Wireshark

**Key classes:**
```java
public final class PcapGlobalHeader {
    // magicNumber, versionMajor, versionMinor, snapLen, network, byteOrder
}

public final class PcapPacketHeader {
    // tsSec, tsUsec, inclLen, origLen
}
```

**Key methods:**
- `PcapReader.open(filename)`: Open PCAP, detect byte order from the magic number, validate the header
- `PcapReader.readNextPacket()`: Read the next packet into a `RawPacket`, or an empty `Optional` at EOF
- `PcapWriter.writeGlobalHeader(header)` / `writePacket(tsSec, tsUsec, data)`: Write an output capture

### `parser/PacketParser.java`

**Purpose:** Extract protocol fields from raw bytes

**Key method:**
```java
public static boolean parse(RawPacket raw, ParsedPacket parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTcp(...);       // Extract ports, flags, seq numbers
    // OR
    parseUdp(...);       // Extract ports
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Ports, sequence numbers, and ack numbers are read out explicitly as big-endian:
```java
private static int readUint16BE(byte[] data, int offset) {
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
}

private static long readUint32BE(byte[] data, int offset) {
    return ((long) (data[offset] & 0xFF) << 24)
            | ((data[offset + 1] & 0xFF) << 16)
            | ((data[offset + 2] & 0xFF) << 8)
            | (data[offset + 3] & 0xFF);
}
```

IPv4 addresses use a different, internally-consistent packing scheme (see `IpAddress`) rather than a textbook big-endian conversion - the same representation is used everywhere the address is parsed, displayed, hashed, or matched against `--block-ip`, so it stays correct end-to-end.

### `dpi/SniExtractor.java` / `dpi/HttpHostExtractor.java`

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```java
public static Optional<String> extract(byte[] payload, int offset, int length) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```java
public static Optional<String> extract(byte[] payload, int offset, int length) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until CRLF
}
```

`DnsExtractor` and `QuicSniExtractor` are also included as complete, working classes for DNS query-name extraction and best-effort QUIC/HTTP3 SNI extraction, available for use even though the default pipeline classifies DNS by port number alone.

### `dpi/AppType.java` / `dpi/FiveTuple.java`

**Purpose:** Define the data structures used throughout the DPI pipeline

**FiveTuple:**
```java
public final class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    // equals()/hashCode() based on all five fields
}
```

**AppType:**
```java
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM, NETFLIX,
    AMAZON, MICROSOFT, APPLE, WHATSAPP, TELEGRAM, TIKTOK,
    SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE
}
```

**`AppType.fromSni()`:**
```java
public static AppType fromSni(String sni) {
    String s = sni.toLowerCase(Locale.ROOT);
    if (s.contains("youtube") || s.contains("ytimg")) return YOUTUBE;
    if (s.contains("facebook") || s.contains("fbcdn"))  return FACEBOOK;
    // ... more patterns, in priority order
    return HTTPS; // recognized as TLS but not one of the known domains
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```java
public static Optional<String> extract(byte[] payload, int offset, int length) {
    // Check TLS record header
    if (!isTlsClientHello(payload, offset, length)) return Optional.empty();

    int pos = 5;       // skip TLS record header
    pos += 4;          // skip handshake type + 3-byte length
    pos += 2;          // skip client version
    pos += 32;         // skip random

    int sessionIdLength = u8(payload, offset + pos);
    pos += 1 + sessionIdLength;

    int cipherSuitesLength = readUint16BE(payload, offset + pos);
    pos += 2 + cipherSuitesLength;

    int compressionMethodsLength = u8(payload, offset + pos);
    pos += 1 + compressionMethodsLength;

    int extensionsLength = readUint16BE(payload, offset + pos);
    pos += 2;

    int extensionsEnd = Math.min(pos + extensionsLength, length);
    while (pos + 4 <= extensionsEnd) {
        int extensionType = readUint16BE(payload, offset + pos);
        int extensionLength = readUint16BE(payload, offset + pos + 2);
        pos += 4;

        if (extensionType == 0x0000) { // SNI!
            int sniLength = readUint16BE(payload, offset + pos + 3);
            String sni = new String(payload, offset + pos + 5, sniLength, StandardCharsets.US_ASCII);
            return Optional.of(sni);
        }

        pos += extensionLength;
    }

    return Optional.empty(); // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|-----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Java 21 JDK**
- **Maven 3.6+**
- No external libraries needed at runtime - `.pcap` reading/writing uses plain `java.io`/`java.nio`, so there's no Npcap/WinPcap/libpcap driver to install

### Build Command

```bash
mvn clean package
```

This produces a single executable jar: `target/packet-analyzer.jar` (default main class: the DPI engine).

### Running

**Basic usage:**
```bash
java -jar target/packet-analyzer.jar test_dpi.pcap output.pcap
```

**With blocking:**
```bash
java -jar target/packet-analyzer.jar test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure threads:**
```bash
java -jar target/packet-analyzer.jar input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

**Basic packet dumper:**
```bash
java -cp target/packet-analyzer.jar com.packetanalyzer.PacketAnalyzerApp test_dpi.pcap 10
```

### Running from IntelliJ IDEA

1. **File → Open...** and select the folder containing `pom.xml` - IntelliJ imports it as a Maven project automatically.
2. Confirm a Java 21 SDK is selected (**File → Project Structure → SDK**).
3. Open `DpiEngineApp.java` (or `PacketAnalyzerApp.java`) and click the green ▶ next to `main()`. Edit the generated run configuration's **Program arguments** to pass your pcap file(s) and flags.

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
+==================================================================+
|              DPI ENGINE v2.0 (Multi-threaded)                 |
+==================================================================+
| Load Balancers:  2    FPs per LB:  2    Total FPs:  4     |
+==================================================================+

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

+==================================================================+
|                      PROCESSING REPORT                        |
+==================================================================+
| Total Packets:                77                           |
| Total Bytes:                5738                           |
| TCP Packets:                  73                           |
| UDP Packets:                   4                           |
+==================================================================+
| Forwarded:                    70                           |
| Dropped:                       7                           |
+==================================================================+
| THREAD STATISTICS                                             |
|   LB0 dispatched:             31                           |
|   LB1 dispatched:             46                           |
|   FP0 processed:              20                           |
|   FP1 processed:              11                           |
|   FP2 processed:              12                           |
|   FP3 processed:              34                           |
+==================================================================+
|                   APPLICATION BREAKDOWN                       |
+==================================================================+
| HTTPS                39  50.6% ##########            |
| Unknown              16  20.8% ####                  |
| DNS                   4   5.2% #                     |
| Twitter/X             3   3.9%                       |
| HTTP                  2   2.6%                       |
| ...                                                  |
+==================================================================+

[Detected Domains/SNIs]
  - www.google.com -> Google
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - github.com -> GitHub
  ...
```

> The report uses plain ASCII box-drawing (`+`, `=`, `|`) instead of Unicode box characters, so it renders correctly in `cmd.exe` without needing `chcp 65001`.

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
```java
   // In AppType.fromSni()
   if (s.contains("twitch")) {
       return AppType.TWITCH; // add TWITCH to the enum first
   }
```

2. **Add Bandwidth Throttling**
```java
   // Instead of dropping, delay packets
   if (shouldThrottle(flow)) {
       Thread.sleep(10);
   }
```

3. **Add a Live Statistics Dashboard**
```java
   // Separate daemon thread printing stats every second
   Thread statsThread = new Thread(() -> {
       while (running) {
           printStats();
           Thread.sleep(1000);
       }
   });
```

4. **Wire Up QUIC/HTTP3 Support**
   - `QuicSniExtractor` already exists and works - it just isn't called from the main classification path yet
   - QUIC uses UDP on port 443; SNI lives inside the Initial packet's CRYPTO frame

5. **Add Persistent Rules**
   - Save `Rules` to a JSON/properties file
   - Load on startup instead of only from CLI flags

6. **Fix the Substring-Matching Classifier**
   - `AppType.fromSni()` matches domains by substring in a fixed priority order, so a domain like `netflix.com` or `microsoft.com` can accidentally match an earlier, unrelated rule (e.g. the Twitter/X check for `x.com`/`t.co`). Switching to proper suffix/domain-boundary matching would remove these false positives.

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with `PacketAnalyzerApp` to understand basic packet parsing, then move to `DpiEngineApp` to see how classification, blocking, and multithreading are added on top.
