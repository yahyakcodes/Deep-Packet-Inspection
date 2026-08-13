package com.packetanalyzer.dpi;

import com.packetanalyzer.util.IpAddress;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Blocking rules: source IPs, application types, and domain substrings.
 * Direct port of the {@code Rules} class defined locally in dpi_mt.cpp
 * (a simpler, self-contained sibling of the more elaborate
 * {@code DPI::RuleManager} in rule_manager.h/.cpp, which is not part of
 * the shipped {@code dpi_engine} - see the project README for details).
 *
 * <p>Thread-safe: read from every fast-path thread, written once at
 * startup from the CLI arguments.
 */
public final class Rules {

    private final Object lock = new Object();
    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final List<String> blockedDomains = new ArrayList<>();

    public void blockIp(String ip) {
        synchronized (lock) {
            blockedIps.add(IpAddress.parseDottedQuad(ip));
        }
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String app) {
        AppType type = AppType.fromDisplayName(app);
        if (type == null) {
            System.err.println("[Rules] Unknown app: " + app);
            return;
        }
        synchronized (lock) {
            blockedApps.add(type);
        }
        System.out.println("[Rules] Blocked app: " + app);
    }

    public void blockDomain(String domain) {
        synchronized (lock) {
            blockedDomains.add(domain);
        }
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isBlocked(int srcIp, AppType app, String sni) {
        synchronized (lock) {
            if (blockedIps.contains(srcIp)) {
                return true;
            }
            if (blockedApps.contains(app)) {
                return true;
            }
            for (String domain : blockedDomains) {
                if (sni != null && sni.contains(domain)) {
                    return true;
                }
            }
            return false;
        }
    }
}
