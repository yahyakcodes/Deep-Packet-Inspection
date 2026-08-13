package com.packetanalyzer.dpi;

import com.packetanalyzer.util.IpAddress;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RulesTest {

    @Test
    void blocksByIp() {
        Rules rules = new Rules();
        rules.blockIp("192.168.1.50");
        int blockedIp = IpAddress.parseDottedQuad("192.168.1.50");
        int otherIp = IpAddress.parseDottedQuad("192.168.1.51");

        assertTrue(rules.isBlocked(blockedIp, AppType.HTTPS, ""));
        assertFalse(rules.isBlocked(otherIp, AppType.HTTPS, ""));
    }

    @Test
    void blocksByApp() {
        Rules rules = new Rules();
        rules.blockApp("YouTube");
        int ip = IpAddress.parseDottedQuad("10.0.0.1");

        assertTrue(rules.isBlocked(ip, AppType.YOUTUBE, "www.youtube.com"));
        assertFalse(rules.isBlocked(ip, AppType.NETFLIX, "www.netflix.com"));
    }

    @Test
    void unknownAppNameIsIgnored() {
        Rules rules = new Rules();
        rules.blockApp("NotARealApp");
        int ip = IpAddress.parseDottedQuad("10.0.0.1");

        assertFalse(rules.isBlocked(ip, AppType.YOUTUBE, "www.youtube.com"));
    }

    @Test
    void blocksByDomainSubstring() {
        Rules rules = new Rules();
        rules.blockDomain("facebook.com");
        int ip = IpAddress.parseDottedQuad("10.0.0.1");

        assertTrue(rules.isBlocked(ip, AppType.FACEBOOK, "www.facebook.com"));
        assertFalse(rules.isBlocked(ip, AppType.GOOGLE, "www.google.com"));
    }
}
