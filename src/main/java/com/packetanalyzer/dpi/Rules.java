package com.packetanalyzer.dpi;

import com.packetanalyzer.util.IpAddress;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Blocking rules: source IPs, application types, and domain substrings.
 * {@code Rules} class defined
 * A simpler, self-contained sibling of the more elaborate
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
