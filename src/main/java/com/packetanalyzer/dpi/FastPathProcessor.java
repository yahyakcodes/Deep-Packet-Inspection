package com.packetanalyzer.dpi;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A single Fast Path (FP) worker thread: connection tracking, DPI
 * classification (SNI/Host extraction), rule matching, and forwarding.
 * Direct port of the {@code FastPath} class defined locally in dpi_mt.cpp.
 *
 * <p>Each instance owns its flow table exclusively (fed only by its own
 * input queue via consistent hashing in {@link LoadBalancer}), so the
 * {@code HashMap} below needs no synchronization - identical reasoning to
 * the original's per-FP {@code flows_} map.
 */
public final class FastPathProcessor {

    private final int id;
    private final Rules rules;
    private final Statistics stats;
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong processed = new AtomicLong();
    private Thread thread;

    public FastPathProcessor(int id, Rules rules, Statistics stats, ThreadSafeQueue<PacketJob> outputQueue) {
        this.id = id;
        this.rules = rules;
        this.stats = stats;
        this.outputQueue = outputQueue;
    }

    public void start() {
        running.set(true);
        thread = new Thread(this::run, "FP-" + id);
        thread.start();
    }

    public void stop() {
        running.set(false);
        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public long getProcessed() {
        return processed.get();
    }

    public int getId() {
        return id;
    }

    private void run() {
        while (running.get()) {
            Optional<PacketJob> maybePacket = inputQueue.pop(100);
            if (maybePacket.isEmpty()) {
                continue;
            }
            processed.incrementAndGet();
            PacketJob pkt = maybePacket.get();

            FlowEntry flow = flows.computeIfAbsent(pkt.getTuple(), FlowEntry::new);
            flow.incrementPackets();
            flow.addBytes(pkt.getData().length);

            if (!flow.isClassified()) {
                classifyFlow(pkt, flow);
            }

            if (!flow.isBlocked()) {
                flow.setBlocked(rules.isBlocked(pkt.getTuple().getSrcIp(), flow.getAppType(), flow.getSni()));
            }

            stats.recordApp(flow.getAppType(), flow.getSni());

            if (flow.isBlocked()) {
                stats.dropped.incrementAndGet();
            } else {
                stats.forwarded.incrementAndGet();
                outputQueue.push(pkt);
            }
        }
    }

    private void classifyFlow(PacketJob pkt, FlowEntry flow) {
        FiveTuple tuple = pkt.getTuple();

        if (tuple.getDstPort() == 443 && pkt.getPayloadLength() > 5) {
            Optional<String> sni = SniExtractor.extract(pkt.getData(), pkt.getPayloadOffset(), pkt.getPayloadLength());
            if (sni.isPresent()) {
                flow.setSni(sni.get());
                flow.setAppType(AppType.fromSni(sni.get()));
                flow.setClassified(true);
                return;
            }
        }

        if (tuple.getDstPort() == 80 && pkt.getPayloadLength() > 10) {
            Optional<String> host = HttpHostExtractor.extract(pkt.getData(), pkt.getPayloadOffset(), pkt.getPayloadLength());
            if (host.isPresent()) {
                flow.setSni(host.get());
                flow.setAppType(AppType.fromSni(host.get()));
                flow.setClassified(true);
                return;
            }
        }

        if (tuple.getDstPort() == 53 || tuple.getSrcPort() == 53) {
            flow.setAppType(AppType.DNS);
            flow.setClassified(true);
            return;
        }

        // Port-based fallback; deliberately NOT marked as classified so a
        // later packet in the flow can still be identified via SNI/Host.
        if (tuple.getDstPort() == 443) {
            flow.setAppType(AppType.HTTPS);
        } else if (tuple.getDstPort() == 80) {
            flow.setAppType(AppType.HTTP);
        }
    }
}
