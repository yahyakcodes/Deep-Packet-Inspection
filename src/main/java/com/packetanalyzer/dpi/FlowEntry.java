package com.packetanalyzer.dpi;

/**
 * Per-flow tracking state, owned exclusively by a single
 * {@link FastPathProcessor} (each fast-path thread has its own flow table,
 * so no synchronization is needed here).
 * {@code FlowEntry} struct defined locally in dpi_mt.java.
 */
public final class FlowEntry {

    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sni = "";
    private long packets = 0;
    private long bytes = 0;
    private boolean blocked = false;
    private boolean classified = false;

    public FlowEntry(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple getTuple() {
        return tuple;
    }

    public AppType getAppType() {
        return appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public String getSni() {
        return sni;
    }

    public void setSni(String sni) {
        this.sni = sni;
    }

    public long getPackets() {
        return packets;
    }

    public void incrementPackets() {
        packets++;
    }

    public long getBytes() {
        return bytes;
    }

    public void addBytes(long n) {
        bytes += n;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public boolean isClassified() {
        return classified;
    }

    public void setClassified(boolean classified) {
        this.classified = classified;
    }
}
