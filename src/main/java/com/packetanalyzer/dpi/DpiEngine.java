package com.packetanalyzer.dpi;

import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.PcapWriter;
import com.packetanalyzer.pcap.RawPacket;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.util.IpAddress;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Multi-threaded DPI engine: reads an input pcap, fans packets out across
 * Load Balancer and Fast Path thread pools for classification/blocking,
 * and writes whatever is not blocked to an output pcap.
 *
 * <p>Direct port of the {@code DPIEngine} class defined locally in
 * dpi_mt.cpp - the actual source of the prebuilt {@code dpi_engine}
 * binary shipped in the original repository (confirmed by the banner
 * text and mangled symbol names embedded in that macOS binary).
 *
 * <p>Architecture (identical to the original):
 * <pre>
 *   Reader (this thread) --hash(tuple)--&gt; LB threads --hash(tuple)--&gt; FP threads --&gt; Output writer thread
 * </pre>
 */
public final class DpiEngine {

    /** Mirrors {@code DPIEngine::Config} in dpi_mt.cpp. */
    public static final class Config {
        private int numLbs = 2;
        private int fpsPerLb = 2;

        public int getNumLbs() {
            return numLbs;
        }

        public void setNumLbs(int numLbs) {
            this.numLbs = numLbs;
        }

        public int getFpsPerLb() {
            return fpsPerLb;
        }

        public void setFpsPerLb(int fpsPerLb) {
            this.fpsPerLb = fpsPerLb;
        }
    }

    private final Config config;
    private final Rules rules = new Rules();
    private final Statistics stats = new Statistics();
    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10_000);
    private final List<FastPathProcessor> fastPaths = new ArrayList<>();
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();

    public DpiEngine(Config config) {
        this.config = config;
        int totalFps = config.numLbs * config.fpsPerLb;

        System.out.println();
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.println("|              DPI ENGINE v2.0 (Multi-threaded)                 |");
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.printf("| Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     |%n",
                config.numLbs, config.fpsPerLb, totalFps);
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.println();

        for (int i = 0; i < totalFps; i++) {
            fastPaths.add(new FastPathProcessor(i, rules, stats, outputQueue));
        }

        for (int lb = 0; lb < config.numLbs; lb++) {
            List<FastPathProcessor> lbFps = new ArrayList<>();
            int start = lb * config.fpsPerLb;
            for (int i = 0; i < config.fpsPerLb; i++) {
                lbFps.add(fastPaths.get(start + i));
            }
            loadBalancers.add(new LoadBalancer(lb, lbFps));
        }
    }

    public void blockIp(String ip) {
        rules.blockIp(ip);
    }

    public void blockApp(String app) {
        rules.blockApp(app);
    }

    public void blockDomain(String domain) {
        rules.blockDomain(domain);
    }

    /**
     * Reads {@code inputFile}, classifies and filters every packet, and
     * writes whatever was not blocked to {@code outputFile}. Direct port
     * of {@code DPIEngine::process()}.
     */
    public boolean process(String inputFile, String outputFile) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            return false;
        }

        PcapWriter writer;
        try {
            writer = new PcapWriter(outputFile);
            writer.writeGlobalHeader(reader.getGlobalHeader());
        } catch (IOException e) {
            System.err.println("Cannot open output file");
            reader.close();
            return false;
        }

        for (FastPathProcessor fp : fastPaths) {
            fp.start();
        }
        for (LoadBalancer lb : loadBalancers) {
            lb.start();
        }

        AtomicBoolean outputRunning = new AtomicBoolean(true);
        Thread outputThread = new Thread(() -> outputWriterLoop(writer, outputRunning), "Output-Writer");
        outputThread.start();

        System.out.println("[Reader] Processing packets...");

        long pktId = 0;
        Optional<RawPacket> next;
        while ((next = reader.readNextPacket()).isPresent()) {
            RawPacket raw = next.get();
            ParsedPacket parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed)) {
                continue;
            }
            if (!parsed.hasIp() || (!parsed.hasTcp() && !parsed.hasUdp())) {
                continue;
            }

            byte[] data = raw.getData();

            int srcIp = IpAddress.parseDottedQuad(parsed.getSrcIp());
            int dstIp = IpAddress.parseDottedQuad(parsed.getDestIp());
            FiveTuple tuple = new FiveTuple(srcIp, dstIp, parsed.getSrcPort(), parsed.getDestPort(), parsed.getProtocol());

            // Recompute the payload offset directly from the raw bytes,
            // exactly like the original DPIEngine::process() does (it does
            // not reuse ParsedPacket's own payload fields for this).
            int payloadOffset = 14; // Ethernet
            int payloadLength = 0;
            if (data.length > 14) {
                int ipIhl = data[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                if (parsed.hasTcp() && payloadOffset + 12 < data.length) {
                    int tcpOff = (data[payloadOffset + 12] >> 4) & 0x0F;
                    payloadOffset += tcpOff * 4;
                } else if (parsed.hasUdp()) {
                    payloadOffset += 8;
                }

                payloadLength = payloadOffset < data.length ? data.length - payloadOffset : 0;
            }

            PacketJob pkt = new PacketJob(pktId++, raw.getHeader().getTsSec(), raw.getHeader().getTsUsec(),
                    tuple, data, parsed.getTcpFlags(), payloadOffset, payloadLength);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(data.length);
            if (parsed.hasTcp()) {
                stats.tcpPackets.incrementAndGet();
            } else if (parsed.hasUdp()) {
                stats.udpPackets.incrementAndGet();
            }

            int lbIndex = Math.floorMod(tuple.hashCode(), loadBalancers.size());
            loadBalancers.get(lbIndex).getInputQueue().push(pkt);
        }

        System.out.println("[Reader] Done reading " + pktId + " packets");
        reader.close();

        // Give the queues a moment to drain, matching the original's fixed
        // 500ms grace period before threads are told to stop.
        sleepQuietly(500);

        for (LoadBalancer lb : loadBalancers) {
            lb.stop();
        }
        for (FastPathProcessor fp : fastPaths) {
            fp.stop();
        }

        outputRunning.set(false);
        outputQueue.shutdown();
        try {
            outputThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        try {
            writer.close();
        } catch (IOException e) {
            System.err.println("Warning: error closing output file: " + e.getMessage());
        }

        printReport();
        return true;
    }

    private void outputWriterLoop(PcapWriter writer, AtomicBoolean outputRunning) {
        while (outputRunning.get() || outputQueue.size() > 0) {
            Optional<PacketJob> maybePacket = outputQueue.pop(50);
            if (maybePacket.isEmpty()) {
                continue;
            }
            PacketJob pkt = maybePacket.get();
            try {
                writer.writePacket(pkt.getTsSec(), pkt.getTsUsec(), pkt.getData());
            } catch (IOException e) {
                System.err.println("Error writing packet to output file: " + e.getMessage());
            }
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void printReport() {
        System.out.println();
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.println("|                      PROCESSING REPORT                        |");
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.printf("| Total Packets:      %12d                           |%n", stats.totalPackets.get());
        System.out.printf("| Total Bytes:        %12d                           |%n", stats.totalBytes.get());
        System.out.printf("| TCP Packets:        %12d                           |%n", stats.tcpPackets.get());
        System.out.printf("| UDP Packets:        %12d                           |%n", stats.udpPackets.get());
        System.out.println("+" + "=".repeat(66) + "+");
        System.out.printf("| Forwarded:          %12d                           |%n", stats.forwarded.get());
        System.out.printf("| Dropped:            %12d                           |%n", stats.dropped.get());

        System.out.println("+" + "=".repeat(66) + "+");
        System.out.println("| THREAD STATISTICS                                             |");
        for (LoadBalancer lb : loadBalancers) {
            System.out.printf("|   LB%d dispatched:   %12d                           |%n", lb.getId(), lb.getDispatched());
        }
        for (FastPathProcessor fp : fastPaths) {
            System.out.printf("|   FP%d processed:    %12d                           |%n", fp.getId(), fp.getProcessed());
        }

        System.out.println("+" + "=".repeat(66) + "+");
        System.out.println("|                   APPLICATION BREAKDOWN                       |");
        System.out.println("+" + "=".repeat(66) + "+");

        Map<AppType, Long> appCounts = stats.snapshotAppCounts();
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        long total = stats.totalPackets.get();
        for (Map.Entry<AppType, Long> entry : sortedApps) {
            AppType app = entry.getKey();
            long count = entry.getValue();
            double pct = total > 0 ? (100.0 * count / total) : 0.0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(Math.max(0, barLen));
            System.out.printf("| %-15s%8d %5.1f%% %-20s  |%n",
                    app.getDisplayName(), count, pct, bar);
        }

        System.out.println("+" + "=".repeat(66) + "+");

        Map<String, AppType> detected = stats.snapshotDetectedSnis();
        if (!detected.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Domains/SNIs]");
            for (Map.Entry<String, AppType> entry : detected.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().getDisplayName());
            }
        }
    }
}
