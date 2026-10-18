package com.packetanalyzer.dpi;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe processing statistics. {@code Stats}
 **/
public final class Statistics {

    public final AtomicLong totalPackets = new AtomicLong();
    public final AtomicLong totalBytes = new AtomicLong();
    public final AtomicLong forwarded = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public final AtomicLong tcpPackets = new AtomicLong();
    public final AtomicLong udpPackets = new AtomicLong();

    private final Object appLock = new Object();
    private final Map<AppType, Long> appCounts = new LinkedHashMap<>();
    private final Map<String, AppType> detectedSnis = new LinkedHashMap<>();

    public void recordApp(AppType app, String sni) {
        synchronized (appLock) {
            appCounts.merge(app, 1L, Long::sum);
            if (sni != null && !sni.isEmpty()) {
                detectedSnis.put(sni, app);
            }
        }
    }

    /** Snapshot of app -> packet-count, safe to iterate outside the lock. */
    public Map<AppType, Long> snapshotAppCounts() {
        synchronized (appLock) {
            return new LinkedHashMap<>(appCounts);
        }
    }

    /** Snapshot of detected SNI/Host -> app-type. */
    public Map<String, AppType> snapshotDetectedSnis() {
        synchronized (appLock) {
            return new LinkedHashMap<>(detectedSnis);
        }
    }
}
