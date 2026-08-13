package com.packetanalyzer.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IpAddressTest {

    @Test
    void parseDottedQuadThenToDottedQuadRoundTrips() {
        int packed = IpAddress.parseDottedQuad("192.168.1.50");
        assertEquals("192.168.1.50", IpAddress.toDottedQuad(packed));
    }

    @Test
    void packOctetsMatchesParseDottedQuad() {
        int fromOctets = IpAddress.packOctets(10, 0, 0, 1);
        int fromString = IpAddress.parseDottedQuad("10.0.0.1");
        assertEquals(fromOctets, fromString);
    }

    @Test
    void handlesLoopback() {
        int packed = IpAddress.parseDottedQuad("127.0.0.1");
        assertEquals("127.0.0.1", IpAddress.toDottedQuad(packed));
    }

    @Test
    void handlesBroadcastLikeAddress() {
        int packed = IpAddress.parseDottedQuad("255.255.255.255");
        assertEquals("255.255.255.255", IpAddress.toDottedQuad(packed));
    }
}
