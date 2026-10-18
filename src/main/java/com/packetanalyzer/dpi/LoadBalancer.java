package com.packetanalyzer.dpi;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A single Load Balancer (LB) worker thread: pops packets from its own
 * input queue (fed by the reader) and consistently hashes each one's
 * five-tuple to pick which Fast Path thread should own that flow.
 * {@code LoadBalancer} class defined.
 */
public final class LoadBalancer {

    private final int id;
    private final List<FastPathProcessor> fastPaths;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong dispatched = new AtomicLong();
    private Thread thread;

    public LoadBalancer(int id, List<FastPathProcessor> fastPaths) {
        this.id = id;
        this.fastPaths = fastPaths;
    }

    public void start() {
        running.set(true);
        thread = new Thread(this::run, "LB-" + id);
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

    public long getDispatched() {
        return dispatched.get();
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
            PacketJob pkt = maybePacket.get();
            int fpIndex = Math.floorMod(pkt.getTuple().hashCode(), fastPaths.size());
            fastPaths.get(fpIndex).getInputQueue().push(pkt);
            dispatched.incrementAndGet();
        }
    }
}
